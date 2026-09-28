import { create } from 'zustand';
import type { HttpResult, ProxyDetails, ProxyStatus, ScanResult, Progress, DpiProfile, DpiResult, DpiReport } from '@/types/dashboard';

export type TaskStatus = 'idle' | 'starting' | 'running' | 'stopping';
export type SseState = 'connecting' | 'live' | 'reconnecting';

const emptyProgress: Progress = { completed: 0, total: 0 };

interface RuntimeState {
    proxyStatus: ProxyStatus;
    proxyDetails: ProxyDetails | null;
    proxyError: string | null;

    httpStatus: TaskStatus;
    httpProgress: Progress;
    httpResults: HttpResult[];
    httpError: string | null;

    scanStatus: TaskStatus;
    scanProgress: Progress;
    /** Successful scan results only; failures are just counted. */
    scanResults: ScanResult[];
    scanFailed: number;
    scanError: string | null;

    dpiStatus: TaskStatus;
    /** Profiles announced at the start of a run (for progress). */
    dpiProfiles: DpiProfile[];
    dpiResults: DpiResult[];
    dpiReport: DpiReport | null;
    dpiError: string | null;
    dpiLink: string;
    dpiProgress: { done: number; total: number };

    sse: SseState;
    /** Epoch ms of the next reconnect attempt while reconnecting. */
    sseRetryAt: number | null;
    /** True once the first state sync with the server completed. */
    synced: boolean;
}

interface RuntimeActions {
    setProxyStatus: (s: ProxyStatus, error?: string | null) => void;
    setProxyDetails: (d: ProxyDetails | null) => void;

    setHttpStatus: (s: TaskStatus, error?: string | null) => void;
    setHttpProgress: (p: Progress) => void;
    upsertHttpResults: (batch: HttpResult[]) => void;
    replaceHttpResults: (all: HttpResult[]) => void;
    clearHttpResults: () => void;

    setScanStatus: (s: TaskStatus, error?: string | null) => void;
    setScanProgress: (p: Progress) => void;
    upsertScanResults: (batch: ScanResult[]) => void;
    replaceScanResults: (all: ScanResult[]) => void;
    clearScanResults: () => void;

    setDpiStatus: (s: TaskStatus, error?: string | null) => void;
    startDpiRun: (link: string) => void;
    setDpiProfiles: (p: DpiProfile[]) => void;
    upsertDpiResults: (batch: DpiResult[]) => void;
    setDpiReport: (r: DpiReport | null) => void;
    setDpiProgress: (p: { done?: number; total?: number }) => void;

    setSse: (s: SseState, retryAt?: number | null) => void;
    setSynced: () => void;
    reset: () => void;
}

// Row indexes live beside the arrays so an upsert is O(batch) lookups plus one
// array copy, not an O(n) filter per incoming event.
let httpIndex = new Map<string, number>();
let scanIndex = new Map<string, number>();

function upsert<T>(list: T[], index: Map<string, number>, batch: T[], key: (t: T) => string): T[] {
    if (batch.length === 0) return list;
    const next = list.slice();
    for (const item of batch) {
        const k = key(item);
        const at = index.get(k);
        if (at === undefined) {
            index.set(k, next.length);
            next.push(item);
        } else {
            next[at] = item;
        }
    }
    return next;
}

function rebuild<T>(list: T[], key: (t: T) => string): Map<string, number> {
    const m = new Map<string, number>();
    list.forEach((t, i) => m.set(key(t), i));
    return m;
}

const httpKey = (r: HttpResult) => r.link;
const scanKey = (r: ScanResult) => r.ip;

const initialState: RuntimeState = {
    proxyStatus: 'stopped',
    proxyDetails: null,
    proxyError: null,
    httpStatus: 'idle',
    httpProgress: emptyProgress,
    httpResults: [],
    httpError: null,
    scanStatus: 'idle',
    scanProgress: emptyProgress,
    scanResults: [],
    scanFailed: 0,
    scanError: null,
    dpiStatus: 'idle',
    dpiProfiles: [],
    dpiResults: [],
    dpiReport: null,
    dpiError: null,
    dpiLink: '',
    dpiProgress: { done: 0, total: 0 },
    sse: 'connecting',
    sseRetryAt: null,
    synced: false,
};

export const useRuntimeStore = create<RuntimeState & RuntimeActions>()((set) => ({
    ...initialState,

    setProxyStatus: (s, error) => set((st) => ({
        proxyStatus: s,
        proxyError: error === undefined ? (s === 'starting' ? null : st.proxyError) : error,
        ...(s === 'stopped' ? { proxyDetails: null } : {}),
    })),
    setProxyDetails: (d) => set({ proxyDetails: d }),

    setHttpStatus: (s, error) => set((st) => ({
        httpStatus: s,
        httpError: error === undefined ? (s === 'starting' ? null : st.httpError) : error,
        ...(s === 'starting' ? { httpProgress: emptyProgress } : {}),
    })),
    setHttpProgress: (p) => set({ httpProgress: p }),
    upsertHttpResults: (batch) => set((st) => ({ httpResults: upsert(st.httpResults, httpIndex, batch, httpKey) })),
    replaceHttpResults: (all) => {
        httpIndex = rebuild(all, httpKey);
        set({ httpResults: all });
    },
    clearHttpResults: () => {
        httpIndex = new Map();
        set({ httpResults: [], httpProgress: emptyProgress });
    },

    setScanStatus: (s, error) => set((st) => ({
        scanStatus: s,
        scanError: error === undefined ? (s === 'starting' ? null : st.scanError) : error,
        ...(s === 'starting' ? { scanProgress: emptyProgress } : {}),
    })),
    setScanProgress: (p) => set({ scanProgress: p }),
    upsertScanResults: (batch) => set((st) => {
        const ok: ScanResult[] = [];
        let failed = 0;
        for (const r of batch) {
            if (r.error) {
                // A later failure (e.g. a speed test error) must not erase an IP
                // that already passed latency.
                if (!scanIndex.has(r.ip)) failed++;
            } else ok.push(r);
        }
        return { scanResults: upsert(st.scanResults, scanIndex, ok, scanKey), scanFailed: st.scanFailed + failed };
    }),
    replaceScanResults: (all) => {
        const ok = all.filter((r) => !r.error);
        scanIndex = rebuild(ok, scanKey);
        set({ scanResults: ok, scanFailed: all.length - ok.length });
    },
    clearScanResults: () => {
        scanIndex = new Map();
        set({ scanResults: [], scanFailed: 0, scanProgress: emptyProgress });
    },

    setDpiStatus: (s, error) => set((st) => ({
        dpiStatus: s,
        dpiError: error === undefined ? (s === 'starting' ? null : st.dpiError) : error,
    })),
    startDpiRun: (link) => set({ dpiStatus: 'starting', dpiError: null, dpiProfiles: [], dpiResults: [], dpiReport: null, dpiLink: link, dpiProgress: { done: 0, total: 0 } }),
    setDpiProgress: (p) => set((st) => ({ dpiProgress: { done: p.done ?? st.dpiProgress.done, total: p.total ?? st.dpiProgress.total } })),
    setDpiProfiles: (p) => set({ dpiProfiles: p }),
    upsertDpiResults: (batch) => set((st) => {
        if (batch.length === 0) return st;
        const byIndex = new Map(st.dpiResults.map((r) => [r.index, r]));
        for (const r of batch) byIndex.set(r.index, r);
        return { dpiResults: [...byIndex.values()].sort((a, b) => a.index - b.index) };
    }),
    setDpiReport: (r) => set((st) => ({ dpiReport: r, ...(r ? { dpiResults: r.results?.length ? r.results : st.dpiResults, dpiLink: r.link || st.dpiLink } : {}) })),

    setSse: (s, retryAt = null) => set({ sse: s, sseRetryAt: retryAt }),
    setSynced: () => set({ synced: true }),
    reset: () => {
        httpIndex = new Map();
        scanIndex = new Map();
        set(initialState);
    },
}));

export const isTaskBusy = (s: TaskStatus) => s !== 'idle';
