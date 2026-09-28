import { useEffect, useMemo, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { toast } from "sonner";
import { Play, Square, Loader2, ScanSearch, Copy, Wand2, Server, Globe, CircleCheck, CircleX, CircleDashed, ChevronDown, Trophy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { InputNumber } from "@/components/ui/input-number";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuLabel, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Panel } from "@/components/common/Panel";
import { Field, CheckRow } from "@/components/common/Field";
import { Collapsible } from "@/components/common/Collapsible";
import { EmptyState } from "@/components/common/EmptyState";
import { SplitView } from "@/components/common/SplitView";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useSettingsStore } from "@/stores/settingsStore";
import { usePersistentState } from "@/hooks/usePersistentState";
import { api, isMissingEndpoint, type DpiStartRequest, type DpiDefaults } from "@/services/api";
import { isLikelyLink } from "@/lib/links";
import { settingsFromFragment, xrayFragmentSnippet } from "@/lib/fragment";
import { toastStartError, waitUntilIdle } from "@/lib/runControl";
import { cn, copyText, errorMessage, formatMs } from "@/lib/utils";
import type { DpiResult, DpiDirectCheck, DpiProfile } from "@/types/dashboard";
import type { FragmentOptions } from "@/types/settings";
import type { Page } from "@/hooks/useHashRoute";
import { FAILURE_LABELS, RESULT_STATUS, VERDICTS, statusRank } from "./verdict";
import { useT } from "@/i18n";

interface DpiForm {
    link: string;
    mode: "quick" | "full";
    attempts: number;
    threads: number;
    timeout: number;
    testURL: string;
    specs: string;
    snis: string;
    mixedCaseSNI: boolean;
    stopAfter: number;
    core: "auto" | "xray" | "sing-box";
    insecureTLS: boolean;
}

const DEFAULT_FORM: DpiForm = {
    link: "", mode: "quick", attempts: 3, threads: 2, timeout: 8000, testURL: "", specs: "", snis: "",
    mixedCaseSNI: false, stopAfter: 0, core: "auto", insecureTLS: false,
};

/** The CLI flags that reproduce a profile (fragment and/or noise). */
function cliFlags(p: DpiProfile): string {
    if (p.args) return p.args;
    return p.spec ? `--fragment ${p.spec}` : "";
}

function lines(s: string) {
    return s.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
}

function FailureChips({ failures }: { failures?: Record<string, number> }) {
    const t = useT();
    if (!failures) return null;
    const entries = Object.entries(failures).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) return null;
    return (
        <span className="flex flex-wrap gap-1">
            {entries.map(([k, n]) => (
                <span key={k} className="num rounded bg-fail/10 px-1.5 py-0.5 text-[11px] text-fail">{t(FAILURE_LABELS[k] ?? k)} ×{n}</span>
            ))}
        </span>
    );
}

function DirectCheck({ d }: { d: DpiDirectCheck }) {
    const t = useT();
    if (!d.checked) return null;
    const step = (ok: boolean, label: string, detail: string) => (
        <li className="flex items-start gap-2 text-sm">
            {ok ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-pass" aria-hidden /> : <CircleX className="mt-0.5 size-4 shrink-0 text-fail" aria-hidden />}
            <span><span className="font-medium">{label}</span> <span className="text-muted-foreground">{detail}</span></span>
        </li>
    );
    return (
        <div className="rounded-md border p-3">
            <p className="mb-2 text-xs text-muted-foreground">{t("Direct check of {addr} over {tr}, without the proxy protocol", { addr: d.address, tr: d.transport || "tcp" })}</p>
            <ul className="space-y-1.5">
                {step(d.tcpOk, t("TCP connect"), d.tcpOk ? formatMs(d.tcpDelay) : d.tcpError || t("failed"))}
                {d.tlsChecked && step(d.tlsOk, t("TLS handshake"), d.tlsOk ? `${formatMs(d.tlsDelay)}${d.sni ? ` (SNI ${d.sni})` : ""}` : `${d.tlsKind ? `${t(FAILURE_LABELS[d.tlsKind] ?? d.tlsKind)}: ` : ""}${d.tlsError || t("failed")}`)}
            </ul>
        </div>
    );
}

export default function DpiPage({ navigate }: { navigate: (p: Page) => void }) {
    const t = useT();
    const [form, setForm] = usePersistentState<DpiForm>("dpi-form", DEFAULT_FORM);
    const f = { ...DEFAULT_FORM, ...form, core: (form.core as string) === "singbox" ? "sing-box" : form.core ?? "auto" } as DpiForm;
    const set = (patch: Partial<DpiForm>) => setForm({ ...f, ...patch });
    const { status, profiles, results, report, error, progress } = useRuntimeStore(useShallow((s) => ({
        status: s.dpiStatus, profiles: s.dpiProfiles, results: s.dpiResults, report: s.dpiReport, error: s.dpiError, progress: s.dpiProgress,
    })));
    const [missing, setMissing] = useState(false);
    const [defaults, setDefaults] = useState<DpiDefaults | null>(null);
    const [runKey, setRunKey] = useState(0);
    const busy = status !== "idle";

    useEffect(() => {
        api.dpiStatus().catch((err) => { if (isMissingEndpoint(err)) setMissing(true); });
        api.dpiDefaults().then(setDefaults).catch(() => setDefaults(null));
    }, []);

    const ranked = useMemo(
        () => [...results].sort((a, b) => statusRank(a.status) - statusRank(b.status) || (a.medianDelay || 1e9) - (b.medianDelay || 1e9) || a.index - b.index),
        [results],
    );
    const breakdown = useMemo(() => {
        const m: Record<string, number> = {};
        for (const r of results) for (const [k, n] of Object.entries(r.failures ?? {})) m[k] = (m[k] ?? 0) + n;
        return m;
    }, [results]);
    const total = progress.total || profiles.length || (report?.results.length ?? 0);
    const done = progress.done || results.filter((r) => r.status !== "skipped").length;
    const modeCount = (m: string) => defaults?.modes?.[m]?.length;
    const best = report?.best ?? null;

    const start = async () => {
        const link = f.link.trim();
        if (!isLikelyLink(link)) { toast.error(t("Paste one share link that you know works elsewhere")); return; }
        const req: DpiStartRequest = {
            link, mode: f.mode, attempts: f.attempts, threads: f.threads, timeoutMs: f.timeout,
            testURL: f.testURL.trim() || undefined, specs: lines(f.specs), snis: lines(f.snis),
            mixedCaseSNI: f.mixedCaseSNI, stopAfter: f.stopAfter, core: f.core, insecure: f.insecureTLS,
        };
        useRuntimeStore.getState().startDpiRun(link);
        setRunKey((k) => k + 1);
        try {
            await api.startDpi(req);
            if (useRuntimeStore.getState().dpiStatus === "starting") useRuntimeStore.getState().setDpiStatus("running");
        } catch (err) {
            if (isMissingEndpoint(err)) setMissing(true);
            useRuntimeStore.getState().setDpiStatus("idle", errorMessage(err));
            toastStartError(err, t("DPI finder"));
        }
    };

    const stop = async () => {
        useRuntimeStore.getState().setDpiStatus("stopping");
        try { await api.stopDpi(); } catch { /* resolved by polling */ }
        void waitUntilIdle(async () => (await api.dpiStatus()).status, (st) => useRuntimeStore.getState().setDpiStatus(st), () => useRuntimeStore.getState().dpiStatus === "stopping");
    };

    const applyTo = (target: "http" | "proxy", r: DpiResult) => {
        const frag = settingsFromFragment((r.profile.fragment ?? null) as FragmentOptions | null);
        if (target === "http") useSettingsStore.getState().updateHttpSettings({ fragment: frag });
        else useSettingsStore.getState().updateProxySettings({ fragment: frag });
        toast.success(frag.enabled ? t("Fragment setting applied") : t("Fragmentation turned off"), {
            description: r.profile.sni ? t("This setting also changes the SNI to {sni}; edit your links for that part.", { sni: r.profile.sni }) : undefined,
        });
        navigate(target);
    };

    const copy = async (text: string, what: string) => {
        try { await copyText(text); toast.success(t("Copied {what}", { what })); }
        catch (err) { toast.error(t("Could not copy"), { description: errorMessage(err) }); }
    };

    const actions = (r: DpiResult, compact = false) => (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button size={compact ? "icon-sm" : "sm"} variant={compact ? "ghost" : "default"} aria-label={compact ? t("Use this setting") : undefined}>
                    {compact ? <ChevronDown aria-hidden /> : <><Wand2 aria-hidden />{t("Use this setting")}<ChevronDown aria-hidden className="opacity-70" /></>}
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={() => applyTo("http", r)}><Globe aria-hidden />{t("Apply to the HTTP tester")}</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => applyTo("proxy", r)}><Server aria-hidden />{t("Apply to the proxy")}</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>{t("Copy")}</DropdownMenuLabel>
                <DropdownMenuItem disabled={!cliFlags(r.profile)} onSelect={() => copy(cliFlags(r.profile), t("the CLI flag"))}><Copy aria-hidden />{t("CLI flag")} <code className="ms-auto text-[11px] text-muted-foreground">{r.profile.fragment?.packets ? "--fragment" : "--noise"}</code></DropdownMenuItem>
                <DropdownMenuItem disabled={!r.profile.fragment} onSelect={() => r.profile.fragment && copy(xrayFragmentSnippet(r.profile.fragment as FragmentOptions), t("the xray snippet"))}><Copy aria-hidden />{t("xray JSON outbound")}</DropdownMenuItem>
                {r.link && <DropdownMenuItem onSelect={() => copy(r.link!, t("the link"))}><Copy aria-hidden />{t("Link with this SNI")}</DropdownMenuItem>}
            </DropdownMenuContent>
        </DropdownMenu>
    );

    if (missing) {
        return (
            <Panel title={t("DPI finder")}>
                <EmptyState icon={ScanSearch} title={t("This server has no DPI finder API")}>{t("Update xray-knife, or run `xray-knife dpi` on the command line.")}</EmptyState>
            </Panel>
        );
    }

    const verdict = report ? VERDICTS[report.verdict] ?? { title: report.verdict, tone: "neutral" as const } : null;
    const setup = (
        <Panel title={t("Find a setting that gets through")} description={t("Tests one config with many TLS fragment settings and reports which ones pass on this network.")} bodyClassName="space-y-5">
            <fieldset disabled={busy} className="space-y-5">
                <Field id="dpi-link" label={t("A config to test")} hint={t("Use a config that works on another network. The finder tells you whether this network blocks it and how to get around that.")}>
                    <Textarea id="dpi-link" rows={3} value={f.link} onChange={(e) => set({ link: e.target.value })} placeholder="vless://…" dir="ltr" className="font-mono text-xs md:text-xs" spellCheck={false} />
                </Field>
                <Field id="dpi-mode" label={t("Search")}>
                    <Select value={f.mode} onValueChange={(v) => set({ mode: v as DpiForm["mode"] })}>
                        <SelectTrigger id="dpi-mode"><SelectValue /></SelectTrigger>
                        <SelectContent>
                            <SelectItem value="quick">{modeCount("quick") ? t("Quick: {n} proven settings", { n: modeCount("quick")! }) : t("Quick: about a dozen proven settings")}</SelectItem>
                            <SelectItem value="full">{modeCount("full") ? t("Full: {n} settings, every combination (slow)", { n: modeCount("full")! }) : t("Full: every packets, length and interval combination (slow)")}</SelectItem>
                        </SelectContent>
                    </Select>
                </Field>
                <Collapsible title={t("Advanced")} summary={t("{a} attempts each, {n} at a time", { a: f.attempts, n: f.threads })}>
                    <div className="grid grid-cols-2 gap-3">
                        <Field id="dpi-attempts" label={t("Attempts per setting")} hint={t("Catches DPI that lets the first handshake through")}>
                            <InputNumber id="dpi-attempts" label={t("Attempts")} min={1} max={20} value={f.attempts} onChange={(v) => set({ attempts: v })} />
                        </Field>
                        <Field id="dpi-threads" label={t("Settings in parallel")} hint={t("Keep it low: bursts can trigger blocking")}>
                            <InputNumber id="dpi-threads" label={t("Parallel settings")} min={1} max={16} value={f.threads} onChange={(v) => set({ threads: v })} />
                        </Field>
                        <Field id="dpi-timeout" label={t("Timeout per attempt (ms)")}>
                            <InputNumber id="dpi-timeout" label={t("Timeout")} min={1000} max={60000} step={1000} value={f.timeout} onChange={(v) => set({ timeout: v })} />
                        </Field>
                        <Field id="dpi-stop" label={t("Stop after N working")} hint={t("0 = try everything")}>
                            <InputNumber id="dpi-stop" label={t("Stop after")} min={0} max={100} value={f.stopAfter} onChange={(v) => set({ stopAfter: v })} />
                        </Field>
                        <Field id="dpi-core" label={t("Core")}>
                            <Select value={f.core} onValueChange={(v) => set({ core: v as DpiForm["core"] })}>
                                <SelectTrigger id="dpi-core"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="auto">{t("Automatic")}</SelectItem>
                                    <SelectItem value="xray">Xray</SelectItem>
                                    <SelectItem value="sing-box">sing-box</SelectItem>
                                </SelectContent>
                            </Select>
                        </Field>
                    </div>
                    <Field id="dpi-url" label={t("Test URL")} hint={t("Empty = {url}", { url: defaults?.testURL ?? "https://www.gstatic.com/generate_204" })}>
                        <Input id="dpi-url" value={f.testURL} onChange={(e) => set({ testURL: e.target.value })} placeholder={defaults?.testURL ?? "https://www.gstatic.com/generate_204"} dir="ltr" className="font-mono text-xs md:text-xs" />
                    </Field>
                    <Field id="dpi-specs" label={t("Your own fragment settings (optional)")} hint={t("One per line as packets,length,interval. Replaces the built-in list. \"none\" tries the config without fragmentation.")}>
                        <Textarea id="dpi-specs" rows={3} value={f.specs} onChange={(e) => set({ specs: e.target.value })} placeholder={"tlshello,100-200,10-20\n1-3,1-5,1-2"} dir="ltr" className="font-mono text-xs md:text-xs" spellCheck={false} />
                    </Field>
                    <Field id="dpi-snis" label={t("Extra SNIs to try (optional)")} hint={t("One per line. Each is tried with every fragment setting.")}>
                        <Textarea id="dpi-snis" rows={2} value={f.snis} onChange={(e) => set({ snis: e.target.value })} placeholder="www.speedtest.net" dir="ltr" className="font-mono text-xs md:text-xs" spellCheck={false} />
                    </Field>
                    <CheckRow id="dpi-mixed" label={t("Also try the SNI in mixed case")} hint={t("Some filters match the name case-sensitively.")}>
                        <Checkbox id="dpi-mixed" checked={f.mixedCaseSNI} onCheckedChange={(c) => set({ mixedCaseSNI: Boolean(c) })} />
                    </CheckRow>
                    <CheckRow id="dpi-insecure" label={t("Allow insecure TLS")}>
                        <Checkbox id="dpi-insecure" checked={f.insecureTLS} onCheckedChange={(c) => set({ insecureTLS: Boolean(c) })} />
                    </CheckRow>
                </Collapsible>
            </fieldset>
            <div className="space-y-3">
                <div className="flex gap-2">
                    {status === "idle"
                        ? <Button className="flex-1" onClick={start}><Play aria-hidden />{t("Find settings")}</Button>
                        : <Button className="flex-1" disabled><Loader2 className="animate-spin" aria-hidden />{status === "stopping" ? t("Stopping…") : status === "starting" ? t("Starting…") : t("Trying settings…")}</Button>}
                    <Button variant="stop" onClick={stop} disabled={status !== "running" && status !== "starting"}><Square aria-hidden />{t("Stop")}</Button>
                </div>
                {busy && total > 0 && (
                    <div className="space-y-1.5" aria-live="polite">
                        <div className="flex justify-between text-xs text-muted-foreground"><span>{t("Settings tried")}</span><span className="num">{done} / {total}</span></div>
                        <Progress value={(done / total) * 100} aria-label={t("DPI finder progress")} />
                    </div>
                )}
                {error && !busy && <p role="alert" className="text-sm text-fail">{error}</p>}
            </div>
        </Panel>
    );

    const resultsPane = (
        <div className="space-y-4">
            {report && verdict && (
                <Panel className={cn(verdict.tone === "pass" && "border-pass/40", verdict.tone === "fail" && "border-fail/40", verdict.tone === "semi" && "border-semi/40")}>
                    <div className="space-y-4">
                        <div className="flex items-start gap-3">
                            {verdict.tone === "pass" ? <CircleCheck className="mt-0.5 size-6 shrink-0 text-pass" aria-hidden /> : verdict.tone === "fail" ? <CircleX className="mt-0.5 size-6 shrink-0 text-fail" aria-hidden /> : <CircleDashed className="mt-0.5 size-6 shrink-0 text-semi" aria-hidden />}
                            <div className="min-w-0 space-y-1">
                                <h2 className="text-base font-semibold leading-6">{t(verdict.title)}</h2>
                                {report.advice && <p className="text-sm text-muted-foreground">{report.advice}</p>}
                                <p className="text-xs text-muted-foreground">{report.protocol} {t("via {core}", { core: report.core })}{report.duration > 0 && `, ${t("took {t}", { t: formatMs(report.duration / 1e6) })}`}</p>
                            </div>
                        </div>
                        {best && (
                            <div className="flex flex-wrap items-center gap-3 rounded-md bg-pass/10 px-3 py-2">
                                <Trophy className="size-4 text-pass" aria-hidden />
                                <div className="min-w-0 flex-1">
                                    <p className="text-sm font-medium">{t("Best setting")}: <code className="font-mono">{best.profile.args || best.profile.spec || t("no fragmentation")}</code>{best.profile.sni && <span className="text-muted-foreground"> SNI {best.profile.sni}</span>}</p>
                                    <p className="num text-xs text-muted-foreground">{t("{ok} of {n} attempts passed, median {d}", { ok: best.successes, n: best.attempts, d: formatMs(best.medianDelay) })}</p>
                                </div>
                                {actions(best)}
                            </div>
                        )}
                        <DirectCheck d={report.direct} />
                    </div>
                </Panel>
            )}
            <Panel
                title={t("Settings tried")}
                description={results.length ? t("Working settings first, then by speed.") : undefined}
                bodyClassName="p-0"
                className="@container"
            >
                {Object.keys(breakdown).length > 0 && (
                    <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2 text-xs">
                        <span className="text-muted-foreground">{t("How attempts failed")}:</span>
                        <FailureChips failures={breakdown} />
                    </div>
                )}
                {ranked.length === 0 ? (
                    <EmptyState icon={ScanSearch} title={busy ? t("Trying the first settings…") : t("No run yet")}>
                        {!busy && t("Paste a config and start. A quick search takes about a minute.")}
                    </EmptyState>
                ) : (
                    <div>
                        <table className="w-full table-fixed text-sm">
                            <thead className="bg-muted/40 text-xs text-muted-foreground">
                                <tr>
                                    <th scope="col" className="px-3 py-2 text-start font-medium">{t("Setting")}</th>
                                    <th scope="col" className="w-[7.5rem] px-3 py-2 text-start font-medium">{t("Result")}</th>
                                    <th scope="col" className="w-[5.5rem] px-3 py-2 text-start font-medium">{t("Median")}</th>
                                    <th scope="col" className="hidden w-[11rem] px-3 py-2 text-start font-medium @2xl:table-cell">{t("Failures")}</th>
                                    <th scope="col" className="w-11"><span className="sr-only">{t("Actions")}</span></th>
                                </tr>
                            </thead>
                            <tbody className="divide-y">
                                {ranked.map((r) => {
                                    const st = RESULT_STATUS[r.status] ?? RESULT_STATUS.error;
                                    return (
                                        <tr key={r.index} className={cn(r.status === "pass" && "bg-pass/5")}>
                                            <td className="min-w-0 px-3 py-2">
                                                <code className="block truncate font-mono text-xs">{r.profile.spec || r.profile.args || t("no fragmentation")}{r.profile.sni && <span className="ms-2 font-sans text-muted-foreground">SNI {r.profile.sni}</span>}</code>
                                                {r.lastError && r.status !== "pass" && <span dir="ltr" className="block truncate text-start text-[11px] text-muted-foreground" title={r.lastError}>{r.lastError}</span>}
                                            </td>
                                            <td className="px-3 py-2"><Badge variant={st.variant}>{t(st.label)}<span className="num opacity-80">{r.successes}/{r.attempts}</span></Badge></td>
                                            <td className="num px-3 py-2">{r.successes > 0 && r.medianDelay >= 0 ? formatMs(r.medianDelay) : "—"}</td>
                                            <td className="hidden px-3 py-2 @2xl:table-cell"><FailureChips failures={r.failures} /></td>
                                            <td className="px-2 text-end">{(r.status === "pass" || r.status === "partial") && actions(r, true)}</td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </Panel>
        </div>
    );

    return <SplitView resultsSignal={runKey} resultsLabel={results.length || undefined} setup={setup} results={resultsPane} />;
}
