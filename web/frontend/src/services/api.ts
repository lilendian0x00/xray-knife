import { http, ApiError, download } from '@/lib/http';
import type { ProxySettings, HttpTesterSettings, CfScannerSettings } from '@/types/settings';
import type { ProxyDetails, HttpResult, ScanResult, Progress, DpiProfile, DpiResult, DpiReport } from '@/types/dashboard';
import { fragmentPayload } from '@/lib/fragment';

// --- Shapes from the backend contract (scratchpad/web-api.md) ---

export interface Paginated<T> {
    items: T[];
    total: number;
    page: number;
    per_page: number;
}

export interface RunSummary {
    passed: number;
    semiPassed: number;
    failed: number;
    broken: number;
    total: number;
}

export interface ServiceState {
    status: string;
    runId?: number;
    startedAt?: string;
    finishedAt?: string;
    error?: string;
    progress?: Progress & { succeeded?: number; failed?: number };
    summary?: RunSummary;
}

export interface ServerState {
    seq?: number;
    services: {
        proxy?: ServiceState;
        http?: ServiceState;
        cfscan?: ServiceState;
        dpi?: ServiceState;
    };
}

export interface EndpointCheck {
    url: string;
    method?: string;
    expectStatus?: number;
}

export interface ServerInfo {
    version?: string;
    go?: string;
    cores?: string[];
    buildTags?: string[];
    listenAddr?: string;
    tls?: boolean;
    authRequired?: boolean;
    dbAvailable?: boolean;
    allowHostModes?: boolean;
    checkPresets?: Record<string, EndpointCheck[]>;
    protocols?: { scheme: string; core: string }[];
    limits?: { maxThreads?: number; maxScannerThreads?: number; maxIPsPerScan?: number };
}

export interface Subscription {
    id: number;
    url: string;
    remark: string;
    userAgent: string;
    enabled: boolean;
    lastFetchedAt: string | null;
    createdAt: string;
    configCount: number;
}

export interface SubscriptionConfig {
    id: number;
    subscriptionId: number;
    link: string;
    protocol: string;
    remark: string;
    addedAt: string;
    lastSeenAt: string;
}

export interface FetchOptions {
    maxBytes?: number;
    maxLinks?: number;
    timeoutSec?: number;
    proxy?: string;
    userAgent?: string;
}

export interface FetchResult {
    fetched: number;
    saved: number;
    unparsable: number;
    /** Detected document type: plain, base64, clash, singbox, xray. */
    format?: string;
    skipped?: Record<string, number>;
    skipSummary?: string[];
    notModified?: boolean;
    subscription?: Subscription;
    error?: string;
    id?: number;
}

export interface HttpRun {
    id: number;
    startTime: string;
    endTime: string | null;
    configCount: number;
    options?: Record<string, unknown>;
    counts?: RunSummary;
}

export interface HttpRunResult {
    id: number;
    runId: number;
    link: string;
    status: string;
    reason: string;
    delay: number;
    download: number;
    upload: number;
    ip: string;
    location: string;
    ttfb?: number;
    connectTime?: number;
}

export interface CfHistoryRow {
    ip: string;
    latency: number | null;
    download: number | null;
    upload: number | null;
    error: string | null;
    lastScannedAt: string | null;
}

export interface CfRanges {
    ranges: string[];
    v4?: string[];
    v6?: string[];
    source?: 'live' | 'fallback';
    fetchedAt?: string;
}

/** Accepts both the legacy bare array and the paginated envelope. */
function items<T>(data: T[] | Paginated<T> | null | undefined): T[] {
    if (!data) return [];
    return Array.isArray(data) ? data : Array.isArray(data.items) ? data.items : [];
}

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || v === '') continue;
        p.set(k, String(v));
    }
    const s = p.toString();
    return s ? `?${s}` : '';
}

// --- Request builders (exported for tests and re-use) ---

export function buildProxyPayload(settings: ProxySettings, links: string[], useDB = false) {
    const t = settings.inboundTransport;
    return {
        coreType: settings.coreType,
        mode: settings.mode,
        listenAddr: settings.listenAddr.trim() || '127.0.0.1',
        listenPort: settings.listenPort.trim(),
        inboundProtocol: settings.inboundProtocol,
        inboundTransport: settings.inboundProtocol === 'socks' ? '' : t,
        inboundUUID: settings.inboundUUID,
        rotationInterval: settings.rotationInterval,
        maximumAllowedDelay: settings.maximumAllowedDelay,
        batchSize: settings.batchSize,
        concurrency: settings.concurrency,
        healthCheckInterval: settings.healthCheckInterval,
        healthFailThreshold: settings.healthFailThreshold,
        healthCheckUrl: settings.healthCheckUrl.trim() || undefined,
        drainTimeout: settings.drainTimeout,
        blacklistStrikes: settings.blacklistStrikes,
        blacklistDuration: settings.blacklistDuration,
        insecureTLS: settings.insecureTLS,
        enableTls: settings.enableTls,
        tlsCertPath: settings.tlsCertPath,
        tlsKeyPath: settings.tlsKeyPath,
        tlsSni: settings.tlsSni,
        tlsAlpn: settings.tlsAlpn,
        wsPath: t === 'ws' ? settings.transportOptions.ws.path : '',
        wsHost: t === 'ws' ? settings.transportOptions.ws.host : '',
        grpcServiceName: t === 'grpc' ? settings.transportOptions.grpc.serviceName : '',
        grpcAuthority: t === 'grpc' ? settings.transportOptions.grpc.authority : '',
        xhttpMode: t === 'xhttp' ? settings.transportOptions.xhttp.mode : '',
        xhttpHost: t === 'xhttp' ? settings.transportOptions.xhttp.host : '',
        xhttpPath: t === 'xhttp' ? settings.transportOptions.xhttp.path : '',
        chain: settings.chain,
        chainLinks: settings.chain ? settings.chainLinks.trim() : '',
        chainHops: settings.chainHops,
        chainRotation: settings.chainRotation,
        chainAttempts: settings.chainAttempts,
        ...(settings.mode === 'app' || settings.mode === 'host-tun' ? { killSwitch: settings.killSwitch } : {}),
        ...(settings.mode === 'app' && settings.namespaceName.trim() ? { namespaceName: settings.namespaceName.trim() } : {}),
        fragment: fragmentPayload(settings.fragment),
        verbose: true,
        // Both spellings: older servers only read the capitalised field.
        ConfigLinks: links,
        configLinks: links,
        useDB,
    };
}

export const CHECK_PRESETS: Record<string, EndpointCheck[]> = {
    cloudflare: [{ url: 'https://cloudflare.com/cdn-cgi/trace', method: 'GET' }],
    gstatic: [{ url: 'https://www.gstatic.com/generate_204', method: 'GET', expectStatus: 204 }],
    global: [
        { url: 'https://www.gstatic.com/generate_204', method: 'GET', expectStatus: 204 },
        { url: 'https://cloudflare.com/cdn-cgi/trace', method: 'GET' },
        { url: 'http://www.msftconnecttest.com/connecttest.txt', method: 'GET' },
        { url: 'https://captive.apple.com/hotspot-detect.html', method: 'GET' },
    ],
    google: [
        { url: 'https://www.gstatic.com/generate_204', method: 'GET', expectStatus: 204 },
        { url: 'https://www.youtube.com/generate_204', method: 'GET', expectStatus: 204 },
        { url: 'https://play.google.com/generate_204', method: 'GET', expectStatus: 204 },
    ],
    streaming: [
        { url: 'https://www.youtube.com/generate_204', method: 'GET', expectStatus: 204 },
        { url: 'https://www.gstatic.com/generate_204', method: 'GET', expectStatus: 204 },
        { url: 'https://cloudflare.com/cdn-cgi/trace', method: 'GET' },
    ],
};

/** Parses "URL [METHOD] [STATUS]" lines of the custom endpoint panel. */
export function parseEndpointLines(text: string): EndpointCheck[] {
    const out: EndpointCheck[] = [];
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const parts = line.split(/\s+/);
        const check: EndpointCheck = { url: parts[0], method: 'GET' };
        for (const p of parts.slice(1)) {
            if (/^\d{3}$/.test(p)) check.expectStatus = Number(p);
            else if (/^[A-Za-z]+$/.test(p)) check.method = p.toUpperCase();
        }
        out.push(check);
    }
    return out;
}

export interface HttpTestSource {
    links?: string[];
    subscriptionId?: number;
    fromDB?: boolean;
    protocol?: string;
    limit?: number;
}

export function buildHttpTestPayload(settings: HttpTesterSettings, source: HttpTestSource) {
    const panel = settings.checkPreset === 'custom'
        ? parseEndpointLines(settings.customEndpoints)
        : settings.checkPreset !== 'none' ? (CHECK_PRESETS[settings.checkPreset] ?? []) : [];
    return {
        ...source,
        threadCount: settings.threadCount,
        core: settings.coreType,
        maxDelay: settings.maxDelay,
        timeout: settings.timeout,
        retries: settings.retries,
        insecureTLS: settings.insecureTLS,
        speedtest: settings.speedtest,
        speedtestAmount: settings.speedtestAmount,
        speedtestTimeout: settings.speedtestTimeout,
        doIPInfo: settings.doIPInfo,
        destURL: settings.destURL.trim(),
        httpMethod: settings.httpMethod,
        // Named presets go by name (the server's table wins); older servers only
        // know testEndpoints, so the resolved panel is sent as well.
        ...(settings.checkPreset !== 'none' && settings.checkPreset !== 'custom' ? { checkPreset: settings.checkPreset } : {}),
        ...(panel.length > 0 ? { testEndpoints: panel, successThreshold: settings.successThreshold } : {}),
        probeSamples: settings.probeSamples > 1 ? settings.probeSamples : undefined,
        speedtestURL: settings.speedtest && settings.speedtestURL.trim() ? settings.speedtestURL.trim() : undefined,
        prescanTimeout: settings.prescan && settings.prescanTimeout > 0 ? settings.prescanTimeout : undefined,
        saveToDB: settings.saveToDB,
        prescan: settings.prescan,
        maxPassed: settings.maxPassed,
        dedupSemantic: settings.dedup,
        resolver: settings.resolver.trim() || undefined,
        noDiagnose: settings.noDiagnose || undefined,
        fragment: fragmentPayload(settings.fragment),
        verbose: false,
    };
}

export function buildCfScanPayload(settings: CfScannerSettings, subnets: string[], resume: boolean) {
    const configMode = settings.advancedOptions.configLink.trim() !== '';
    return {
        subnets,
        threadCount: settings.threadCount,
        timeout: settings.timeout,
        retry: settings.retry,
        port: settings.port,
        saveToDB: settings.saveToDB,
        doSpeedtest: settings.doSpeedtest,
        speedtestTop: settings.speedtestOptions.top,
        speedtestConcurrency: settings.speedtestOptions.concurrency,
        speedtestTimeout: settings.speedtestOptions.timeout,
        downloadMB: settings.speedtestOptions.downloadMB,
        uploadMB: settings.speedtestOptions.uploadMB,
        configLink: settings.advancedOptions.configLink.trim(),
        insecureTLS: settings.advancedOptions.insecureTLS,
        shuffleIPs: settings.advancedOptions.shuffleIPs,
        shuffleSubnets: settings.advancedOptions.shuffleSubnets,
        fragment: configMode ? fragmentPayload(settings.fragment) : undefined,
        samplePerSubnet: settings.samplePerSubnet > 0 ? settings.samplePerSubnet : undefined,
        maxIPs: settings.maxIPs > 0 ? settings.maxIPs : undefined,
        speedtestURL: settings.doSpeedtest && settings.speedtestURL.trim() ? settings.speedtestURL.trim() : undefined,
        resume,
        verbose: false,
    };
}

export interface DpiStartRequest {
    link: string;
    mode: 'quick' | 'full';
    attempts?: number;
    threads?: number;
    /** Per attempt. */
    timeoutMs?: number;
    testURL?: string;
    /** Overrides the mode's list; "none" = the baseline without fragmentation. */
    specs?: string[];
    snis?: string[];
    mixedCaseSNI?: boolean;
    stopAfter?: number;
    core?: 'auto' | 'xray' | 'sing-box';
    insecure?: boolean;
}

export interface DpiStatusResponse {
    status: string;
    runId?: number;
    total?: number;
    done?: number;
    error?: string;
    profiles?: DpiProfile[] | null;
    results?: DpiResult[] | null;
    report?: DpiReport | null;
}

export interface DpiDefaults {
    testURL: string;
    modes: Record<string, string[]>;
    defaults: { timeoutMs: number; attempts: number; threads: number };
}

export type ExportFormat = 'plain' | 'base64' | 'clash' | 'singbox' | 'xray';

export interface ExportQuery {
    format: ExportFormat;
    status: 'passed' | 'semi-passed' | 'any';
    protocol?: string;
    limit?: number;
    maxAgeHours?: number;
    insecure?: boolean;
}

export interface ExportReport {
    format: string;
    selected: number;
    converted: number;
    skipped: { index: number; name: string; reason: string }[];
    content: string;
}

export interface SubTokenDefaults {
    format?: ExportFormat;
    status?: 'passed' | 'semi-passed' | 'any';
    max?: number;
    subscriptionIds?: number[];
    protocol?: string;
    maxAgeHours?: number;
    updateIntervalHours?: number;
}

export interface SubToken {
    id: string | number;
    name: string;
    prefix: string;
    createdAt: string;
    lastUsedAt: string | null;
    useCount: number;
    defaults: SubTokenDefaults;
}

export interface RestoreResult {
    removed: string[];
    kept: string[];
    errors: string[];
    clean: boolean;
}

function exportPath(ids: number[] | 'all', q: ExportQuery, report: boolean): string {
    const params = {
        format: q.format,
        status: q.status,
        protocol: q.protocol || undefined,
        limit: q.limit && q.limit > 0 ? q.limit : undefined,
        maxAgeHours: q.maxAgeHours && q.maxAgeHours > 0 ? q.maxAgeHours : undefined,
        insecure: q.insecure ? 1 : undefined,
        report: report ? 1 : undefined,
    };
    if (ids !== 'all' && ids.length === 1) return `/api/v1/subscriptions/${ids[0]}/export${qs(params)}`;
    return `/api/v1/configs/export${qs({ ...params, subscriptionId: ids === 'all' ? undefined : ids.join(',') })}`;
}

// --- Endpoints ---

const START_TIMEOUT = 45_000;
// Stop waits up to 30 s (stopWaitTimeout in web/services.go) for a run to wind
// down before answering; give the answer time to arrive.
const STOP_TIMEOUT = 35_000;

export const api = {
    // Auth
    checkAuth: () => http.get<{ auth_required: boolean }>('/api/v1/auth/check', { timeout: 8000, noAuthRedirect: true }),
    login: (username: string, password: string) =>
        http.post<{ token: string; expiresAt?: string }>('/api/v1/login', { username, password }, { noAuthRedirect: true }),
    logout: () => http.post('/api/v1/logout', undefined, { timeout: 5000, noAuthRedirect: true }),

    // Server
    state: () => http.get<ServerState>('/api/v1/state'),
    info: () => http.get<ServerInfo>('/api/v1/info'),

    // Proxy
    startProxy: (settings: ProxySettings, links: string[], useDB = false) =>
        http.post<{ status: string; runId?: number }>('/api/v1/proxy/start', buildProxyPayload(settings, links, useDB), { timeout: START_TIMEOUT }),
    stopProxy: () => http.post('/api/v1/proxy/stop', undefined, { timeout: STOP_TIMEOUT }),
    rotateProxy: () => http.post('/api/v1/proxy/rotate'),
    proxyStatus: () => http.get<{ status: string; runId?: number }>('/api/v1/proxy/status'),
    proxyDetails: () => http.get<ProxyDetails>('/api/v1/proxy/details'),

    // HTTP tester
    startHttpTest: (settings: HttpTesterSettings, source: HttpTestSource) =>
        http.post<{ status: string; runId?: number }>('/api/v1/http/test', buildHttpTestPayload(settings, source), { timeout: START_TIMEOUT }),
    stopHttpTest: () => http.post('/api/v1/http/test/stop', undefined, { timeout: STOP_TIMEOUT }),
    httpTestStatus: () => http.get<{ status: string; runId?: number }>('/api/v1/http/test/status'),
    httpTestHistory: async () => items(await http.get<HttpResult[] | Paginated<HttpResult>>('/api/v1/http/test/history', { timeout: 30_000 })),
    clearHttpTestHistory: () => http.post('/api/v1/http/test/clear_history'),

    // CF scanner
    cfRanges: (v6 = false) => http.get<CfRanges>(`/api/v1/scanner/cf/ranges${v6 ? '?v6=1' : ''}`, { timeout: 20_000 }),
    cfStatus: () => http.get<{ is_scanning: boolean; status?: string; runId?: number }>('/api/v1/scanner/cf/status'),
    cfHistory: async () => items(await http.get<ScanResult[] | Paginated<ScanResult>>('/api/v1/scanner/cf/history', { timeout: 30_000 })),
    startCfScan: (settings: CfScannerSettings, subnets: string[], resume: boolean) =>
        http.post<{ status: string; runId?: number }>('/api/v1/scanner/cf/start', buildCfScanPayload(settings, subnets, resume), { timeout: START_TIMEOUT }),
    stopCfScan: () => http.post('/api/v1/scanner/cf/stop', undefined, { timeout: STOP_TIMEOUT }),
    clearCfHistory: () => http.post('/api/v1/scanner/cf/clear_history'),

    // DPI finder
    startDpi: (req: DpiStartRequest) => http.post<{ status: string; runId?: number }>('/api/v1/dpi/start', req, { timeout: START_TIMEOUT }),
    stopDpi: () => http.post('/api/v1/dpi/stop', undefined, { timeout: STOP_TIMEOUT }),
    dpiStatus: () => http.get<DpiStatusResponse>('/api/v1/dpi/status'),
    dpiDefaults: () => http.get<DpiDefaults>('/api/v1/dpi/defaults'),

    // host-tun deadman
    confirmDeadman: () => http.post('/api/v1/proxy/deadman/confirm'),

    // Subscriptions
    subscriptions: () => http.get<Subscription[]>('/api/v1/subscriptions'),
    addSubscription: (body: { url: string; remark?: string; userAgent?: string }) => http.post<Subscription>('/api/v1/subscriptions', body),
    updateSubscription: (id: number, body: Partial<Pick<Subscription, 'url' | 'remark' | 'userAgent' | 'enabled'>>) =>
        http.patch<Subscription>(`/api/v1/subscriptions/${id}`, body),
    deleteSubscription: (id: number) => http.del(`/api/v1/subscriptions/${id}`),
    fetchSubscription: (id: number, opts: FetchOptions = {}) =>
        http.post<FetchResult>(`/api/v1/subscriptions/${id}/fetch`, opts, { timeout: 180_000 }),
    fetchAllSubscriptions: (opts: FetchOptions = {}) =>
        http.post<{ results: FetchResult[] }>('/api/v1/subscriptions/fetch-all', opts, { timeout: 600_000 }),
    subscriptionConfigs: (id: number, q: { protocol?: string; q?: string; page?: number; per_page?: number } = {}) =>
        http.get<Paginated<SubscriptionConfig>>(`/api/v1/subscriptions/${id}/configs${qs(q)}`),
    testSubscription: (id: number, settings: HttpTesterSettings, source: Omit<HttpTestSource, 'subscriptionId'> = {}) =>
        http.post<{ status: string; runId?: number }>(`/api/v1/subscriptions/${id}/test`, buildHttpTestPayload(settings, source), { timeout: START_TIMEOUT }),

    // Export
    exportReport: (ids: number[] | 'all', q: ExportQuery) => http.get<ExportReport>(exportPath(ids, q, true), { timeout: 120_000 }),
    exportFile: (ids: number[] | 'all', q: ExportQuery) => download(exportPath(ids, q, false), { timeout: 120_000, fallbackName: `xray-knife-sub.${q.format === 'clash' ? 'yaml' : q.format === 'singbox' || q.format === 'xray' ? 'json' : 'txt'}` }),

    // Public subscription tokens
    subTokens: () => http.get<SubToken[]>('/api/v1/sub-tokens'),
    createSubToken: (body: SubTokenDefaults & { name?: string }) =>
        http.post<{ token: string; path: string; subscription?: SubToken; note?: string }>('/api/v1/sub-tokens', body),
    updateSubToken: (id: SubToken['id'], body: { name?: string; defaults?: SubTokenDefaults }) => http.patch<SubToken>(`/api/v1/sub-tokens/${id}`, body),
    revokeSubToken: (id: SubToken['id']) => http.del(`/api/v1/sub-tokens/${id}`),

    // Host-mode cleanup
    restoreProxy: (force = false) => http.post<RestoreResult>('/api/v1/proxy/restore', { force }, { timeout: 60_000 }),

    // DB history
    httpRuns: (page = 1, perPage = 25) => http.get<Paginated<HttpRun>>(`/api/v1/history/http/runs${qs({ page, per_page: perPage })}`),
    httpRunResults: (id: number, q: { status?: string; protocol?: string; q?: string; sort?: string; page?: number; per_page?: number } = {}) =>
        http.get<Paginated<HttpRunResult>>(`/api/v1/history/http/runs/${id}/results${qs(q)}`),
    deleteHttpRun: (id: number) => http.del(`/api/v1/history/http/runs/${id}`),
    cfHistoryDB: (q: { ok?: boolean; sort?: string; page?: number; per_page?: number } = {}) =>
        http.get<Paginated<CfHistoryRow>>(`/api/v1/history/cf${qs({ ...q, ok: q.ok ? 1 : undefined })}`),
    clearCfHistoryDB: () => http.del('/api/v1/history/cf'),
};

export function isMissingEndpoint(err: unknown): boolean {
    return err instanceof ApiError && err.isMissing;
}
