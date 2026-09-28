import { toast } from "sonner";
import { useRuntimeStore, type TaskStatus } from "@/stores/runtimeStore";
import { useLogStore } from "@/stores/logStore";
import { useAuthStore } from "@/stores/authStore";
import { api, type ServerState, type RunSummary } from "@/services/api";
import { ApiError } from "@/lib/http";
import { notifyDone } from "@/lib/notify";
import { failureLabel } from "@/lib/failureKinds";
import type { HttpResult, ProxyDetails, ProxyStatus, ScanResult, Progress, DpiProfile, DpiResult, DpiReport } from "@/types/dashboard";

// Event stream + state sync. One instance for the whole app.
//
// Reconnects forever with capped, jittered backoff. The browser's own
// EventSource reconnect (network blips) keeps Last-Event-ID; when the stream
// was closed for good (server restart, 401) we open a new one and pass the
// last id as ?lastEventId so the server can replay or ask us to resync.

const FLUSH_MS = 250;
const BASE_DELAY = 1000;
const MAX_DELAY = 30_000;
const EVENT_TYPES = [
    "state", "resync", "auth_expired", "log",
    "proxy_status", "proxy_details",
    "http_test_status", "http_test_phase", "http_test_progress", "http_result",
    "cfscan_status", "cf_scan_progress", "cfscan_result",
    "dpi_status", "dpi_profiles", "dpi_start", "dpi_result", "dpi_report",
] as const;

interface Envelope {
    type?: string;
    data?: unknown;
    error?: string;
    message?: string;
    reason?: string;
    summary?: RunSummary;
    failureKinds?: Record<string, number>;
    runId?: number;
    done?: number;
    total?: number;
    verdict?: string;
}

export interface HttpPhase {
    phase: string;
    completed?: number;
    total?: number;
    message?: string;
}

type PhaseListener = (p: HttpPhase | null) => void;

/** Maps the many server spellings onto the UI's task states. */
export function normalizeTaskStatus(s: string | undefined): { status: TaskStatus; terminal: "finished" | "stopped" | "error" | null } {
    switch (s) {
        case "starting": return { status: "starting", terminal: null };
        case "running":
        case "testing":
        case "scanning": return { status: "running", terminal: null };
        case "stopping": return { status: "stopping", terminal: null };
        case "finished": return { status: "idle", terminal: "finished" };
        case "stopped": return { status: "idle", terminal: "stopped" };
        case "error": return { status: "idle", terminal: "error" };
        default: return { status: "idle", terminal: null };
    }
}

function normalizeProxyStatus(s: string | undefined): ProxyStatus {
    if (s === "running" || s === "starting" || s === "stopping") return s;
    return "stopped";
}

function summaryText(s: RunSummary | undefined, kinds?: Record<string, number>): string {
    if (!s) return "";
    const base = `${s.passed} passed, ${s.semiPassed} semi-passed, ${s.failed + s.broken} failed of ${s.total}`;
    const top = Object.entries(kinds ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 3);
    return top.length ? `${base}. Mostly: ${top.map(([k, n]) => `${failureLabel(k).toLowerCase()} ${n}`).join(", ")}` : base;
}

class EventService {
    private es: EventSource | null = null;
    private lastId = "";
    private attempts = 0;
    private retryTimer: number | null = null;
    private flushTimer: number | null = null;
    private httpBuf: HttpResult[] = [];
    private scanBuf: ScanResult[] = [];
    private logBuf: string[] = [];
    private dpiBuf: DpiResult[] = [];
    private stopped = true;
    private syncing: Promise<void> | null = null;
    private phaseListeners = new Set<PhaseListener>();
    private phase: HttpPhase | null = null;

    start() {
        if (!this.stopped) return;
        this.stopped = false;
        this.open();
        this.flushTimer = window.setInterval(() => this.flush(), FLUSH_MS);
        document.addEventListener("visibilitychange", this.onVisible);
    }

    stop() {
        this.stopped = true;
        if (this.retryTimer !== null) window.clearTimeout(this.retryTimer);
        if (this.flushTimer !== null) window.clearInterval(this.flushTimer);
        this.retryTimer = null;
        this.flushTimer = null;
        this.es?.close();
        this.es = null;
        this.flush();
        this.attempts = 0;
        document.removeEventListener("visibilitychange", this.onVisible);
    }

    /** Reconnect immediately (the "Retry now" button). */
    retryNow() {
        if (this.stopped) return;
        if (this.retryTimer !== null) window.clearTimeout(this.retryTimer);
        this.retryTimer = null;
        this.attempts = 0;
        this.es?.close();
        this.es = null;
        this.open();
    }

    onPhase(fn: PhaseListener) {
        this.phaseListeners.add(fn);
        fn(this.phase);
        return () => { this.phaseListeners.delete(fn); };
    }

    private setPhase(p: HttpPhase | null) {
        this.phase = p;
        this.phaseListeners.forEach((fn) => fn(p));
    }

    private onVisible = () => {
        // Tabs in the background can have their stream throttled or dropped.
        if (document.visibilityState === "visible" && !this.stopped && (!this.es || this.es.readyState === EventSource.CLOSED)) {
            this.retryNow();
        }
    };

    private open() {
        const rt = useRuntimeStore.getState();
        rt.setSse(this.attempts === 0 && !rt.synced ? "connecting" : "reconnecting");
        const url = this.lastId ? `/events?lastEventId=${encodeURIComponent(this.lastId)}` : "/events";
        const es = new EventSource(url, { withCredentials: true });
        this.es = es;

        es.onopen = () => {
            this.attempts = 0;
            useRuntimeStore.getState().setSse("live");
            // Older servers don't send a `state` event on connect; sync anyway.
            // A `state` event arriving first makes this a cheap no-op merge.
            void this.sync();
        };
        es.onerror = () => {
            if (this.stopped) return;
            if (es.readyState === EventSource.CONNECTING) {
                // The browser is retrying by itself and keeps Last-Event-ID.
                useRuntimeStore.getState().setSse("reconnecting", Date.now() + 3000);
                return;
            }
            es.close();
            if (this.es === es) this.es = null;
            void this.scheduleReconnect();
        };
        for (const type of EVENT_TYPES) {
            es.addEventListener(type, (e) => this.handle(type, e as MessageEvent));
        }
    }

    private async scheduleReconnect() {
        // A closed stream is often an expired session: check before hammering.
        try {
            await api.proxyStatus();
        } catch (err) {
            if (err instanceof ApiError && err.status === 401) return; // http layer already logged out
        }
        if (this.stopped) return;
        const delay = Math.min(BASE_DELAY * 2 ** this.attempts, MAX_DELAY) * (0.8 + Math.random() * 0.4);
        this.attempts++;
        useRuntimeStore.getState().setSse("reconnecting", Date.now() + delay);
        this.retryTimer = window.setTimeout(() => {
            this.retryTimer = null;
            this.open();
        }, delay);
    }

    private handle(type: string, e: MessageEvent) {
        if (e.lastEventId) this.lastId = e.lastEventId;
        let env: Envelope;
        try {
            env = JSON.parse(e.data) as Envelope;
        } catch {
            if (type === "log" && typeof e.data === "string") this.logBuf.push(e.data);
            return;
        }
        const rt = useRuntimeStore.getState();
        switch (type) {
            case "log":
                if (typeof env.data === "string") this.logBuf.push(env.data);
                break;
            case "state":
                this.applyState(env.data as ServerState);
                break;
            case "resync":
                this.flush();
                void this.sync(true);
                break;
            case "auth_expired":
                this.stop();
                useAuthStore.getState().logout("expired");
                break;
            case "proxy_status": {
                const raw = env.data as string;
                const prev = rt.proxyStatus;
                const next = normalizeProxyStatus(raw);
                const error = raw === "error" || env.error ? (env.error || "The proxy stopped because of an error") : null;
                rt.setProxyStatus(next, error);
                if (error) toast.error("Proxy stopped", { description: error });
                if (next === "running" && prev !== "running") void this.loadProxyDetails();
                break;
            }
            case "proxy_details":
                rt.setProxyDetails(env.data as ProxyDetails);
                break;
            case "http_result":
                this.httpBuf.push(env.data as HttpResult);
                break;
            case "http_test_progress":
                rt.setHttpProgress(env.data as Progress);
                break;
            case "http_test_phase":
                this.setPhase(env.data as HttpPhase);
                break;
            case "http_test_status": {
                this.flush();
                const { status, terminal } = normalizeTaskStatus(env.data as string);
                const prev = rt.httpStatus;
                if (terminal) {
                    this.setPhase(null);
                    const error = terminal === "error" ? (env.error || env.message || "The HTTP test failed") : null;
                    rt.setHttpStatus("idle", error);
                    if (terminal === "error") toast.error("HTTP test failed", { description: error ?? undefined });
                    else if (prev !== "stopping") {
                        const early = env.reason === "max_passed" ? " (stopped early: enough configs passed)" : "";
                        toast.success(terminal === "finished" ? `HTTP test finished${early}` : "HTTP test stopped", {
                            description: summaryText(env.summary, env.failureKinds) || undefined,
                        });
                    }
                    if (terminal === "finished") notifyDone("HTTP test finished", summaryText(env.summary));
                } else {
                    rt.setHttpStatus(status);
                }
                break;
            }
            case "cfscan_result":
                this.scanBuf.push(env.data as ScanResult);
                break;
            case "cf_scan_progress":
                rt.setScanProgress(env.data as Progress);
                break;
            case "dpi_profiles":
            case "dpi_start": {
                const d = env.data as DpiProfile[] | { profiles?: DpiProfile[] };
                rt.setDpiProfiles(Array.isArray(d) ? d : d?.profiles ?? []);
                break;
            }
            case "dpi_result":
                this.dpiBuf.push(env.data as DpiResult);
                if (env.done !== undefined || env.total !== undefined) rt.setDpiProgress({ done: env.done, total: env.total });
                break;
            case "dpi_report":
                this.flush();
                rt.setDpiReport(env.data as DpiReport);
                break;
            case "dpi_status": {
                this.flush();
                // data is {state, total, done}; accept a bare string from older builds.
                const d = env.data as string | { state?: string; total?: number; done?: number };
                const state = typeof d === "string" ? d : d?.state;
                if (typeof d === "object" && d) rt.setDpiProgress({ done: d.done, total: d.total });
                const { status, terminal } = normalizeTaskStatus(state);
                if (terminal) {
                    const error = terminal === "error" ? (env.error || env.message || "The DPI finder failed") : null;
                    rt.setDpiStatus("idle", error);
                    if (error) toast.error("DPI finder failed", { description: error });
                    else if (terminal === "finished") {
                        toast.success("DPI finder finished");
                        notifyDone("DPI finder finished", useRuntimeStore.getState().dpiReport?.advice ?? "");
                    }
                } else {
                    rt.setDpiStatus(status);
                }
                break;
            }
            case "cfscan_status": {
                this.flush();
                const { status, terminal } = normalizeTaskStatus(env.data as string);
                if (terminal) {
                    const error = terminal === "error" ? (env.message || env.error || "The scan failed") : null;
                    const prev = rt.scanStatus;
                    rt.setScanStatus("idle", error);
                    if (error) toast.error("Scan failed", { description: error });
                    else if (terminal === "finished") {
                        toast.success("Cloudflare scan finished");
                        notifyDone("Cloudflare scan finished", `${useRuntimeStore.getState().scanResults.length} responsive IPs`);
                    } else if (prev !== "stopping") toast.info("Cloudflare scan stopped");
                } else {
                    rt.setScanStatus(status);
                }
                break;
            }
        }
    }

    private flush() {
        const rt = useRuntimeStore.getState();
        if (this.httpBuf.length) {
            rt.upsertHttpResults(this.httpBuf);
            this.httpBuf = [];
        }
        if (this.scanBuf.length) {
            rt.upsertScanResults(this.scanBuf);
            this.scanBuf = [];
        }
        if (this.logBuf.length) {
            useLogStore.getState().push(this.logBuf);
            this.logBuf = [];
        }
        if (this.dpiBuf.length) {
            rt.upsertDpiResults(this.dpiBuf);
            this.dpiBuf = [];
        }
    }

    private applyState(state: ServerState | undefined) {
        const svc = state?.services;
        if (!svc) return;
        const rt = useRuntimeStore.getState();
        if (svc.proxy) {
            const next = normalizeProxyStatus(svc.proxy.status);
            rt.setProxyStatus(next, svc.proxy.status === "error" ? svc.proxy.error || null : undefined);
            if (next === "running" && !rt.proxyDetails) void this.loadProxyDetails();
        }
        if (svc.http) {
            const { status, terminal } = normalizeTaskStatus(svc.http.status);
            rt.setHttpStatus(status, terminal === "error" ? svc.http.error || null : undefined);
            if (svc.http.progress) rt.setHttpProgress(svc.http.progress);
        }
        if (svc.cfscan) {
            const { status, terminal } = normalizeTaskStatus(svc.cfscan.status);
            rt.setScanStatus(status, terminal === "error" ? svc.cfscan.error || null : undefined);
            if (svc.cfscan.progress) rt.setScanProgress(svc.cfscan.progress);
        }
        if (svc.dpi) {
            const { status, terminal } = normalizeTaskStatus(svc.dpi.status);
            rt.setDpiStatus(status, terminal === "error" ? svc.dpi.error || null : undefined);
            if (svc.dpi.progress) rt.setDpiProgress({ done: svc.dpi.progress.completed, total: svc.dpi.progress.total });
        }
    }

    private async loadProxyDetails(attempt = 0) {
        try {
            const d = await api.proxyDetails();
            useRuntimeStore.getState().setProxyDetails(d);
        } catch (err) {
            // Details appear a moment after "running"; retry briefly.
            if (attempt < 8 && !(err instanceof ApiError && err.status === 401) && useRuntimeStore.getState().proxyStatus === "running") {
                window.setTimeout(() => void this.loadProxyDetails(attempt + 1), 1000);
            }
        }
    }

    /**
     * Pulls the full server state: statuses and the current result lists.
     * `hard` replaces lists even while a run is active (after a resync).
     */
    sync(hard = false): Promise<void> {
        if (this.syncing) return this.syncing;
        this.syncing = this.doSync(hard).finally(() => { this.syncing = null; });
        return this.syncing;
    }

    private async doSync(hard: boolean) {
        const rt = useRuntimeStore.getState();
        let gotState = false;
        try {
            this.applyState(await api.state());
            gotState = true;
        } catch (err) {
            if (err instanceof ApiError && err.status === 401) return;
        }
        if (!gotState) {
            // Older backend: assemble the state from the per-service endpoints.
            const [p, h, c] = await Promise.allSettled([api.proxyStatus(), api.httpTestStatus(), api.cfStatus()]);
            if (p.status === "fulfilled") {
                const next = normalizeProxyStatus(p.value.status);
                rt.setProxyStatus(next);
                if (next === "running") void this.loadProxyDetails();
            }
            if (h.status === "fulfilled") rt.setHttpStatus(normalizeTaskStatus(h.value.status).status);
            if (c.status === "fulfilled") {
                const st = c.value.status ? normalizeTaskStatus(c.value.status).status : c.value.is_scanning ? "running" : "idle";
                rt.setScanStatus(st);
            }
        }
        const [hist, scans, dpi] = await Promise.allSettled([api.httpTestHistory(), api.cfHistory(), api.dpiStatus()]);
        if (dpi.status === "fulfilled" && dpi.value) {
            const d = dpi.value;
            const r = useRuntimeStore.getState();
            const { status, terminal } = normalizeTaskStatus(d.status);
            r.setDpiStatus(status, terminal === "error" ? d.error || null : undefined);
            r.setDpiProgress({ done: d.done, total: d.total });
            if (d.profiles?.length) r.setDpiProfiles(d.profiles);
            if (d.results?.length) r.upsertDpiResults(d.results);
            if (d.report) r.setDpiReport(d.report);
        }
        this.flush();
        const now = useRuntimeStore.getState();
        if (hist.status === "fulfilled") {
            if (hard || now.httpStatus === "idle" || now.httpResults.length === 0) now.replaceHttpResults(hist.value);
            else now.upsertHttpResults(hist.value);
        }
        if (scans.status === "fulfilled") {
            if (hard || now.scanStatus === "idle" || now.scanResults.length === 0) now.replaceScanResults(scans.value);
            else now.upsertScanResults(scans.value);
        }
        useRuntimeStore.getState().setSynced();
    }
}

export const events = new EventService();
