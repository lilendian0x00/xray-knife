export type ProxyStatus = 'stopped' | 'running' | 'starting' | 'stopping';

export type HttpStatus = 'passed' | 'semi-passed' | 'failed' | 'broken' | 'timeout' | 'canceled';

export interface ProtocolInfo {
    remark: string;
    protocol: string;
    address: string;
    port: string;
}

export interface EndpointResult {
    url: string;
    label: string;
    outcome: 'ok' | 'slow' | 'bad-status' | 'error';
    code: number;
    delay: number;
    reason?: string;
}

export interface HttpResult {
    link: string;
    status: HttpStatus;
    reason: string;
    tls: string;
    ip: string;
    delay: number;
    code?: number;
    download: number;
    upload: number;
    location: string;
    colo?: string;
    /** WARP state from the Cloudflare trace: off, on or plus. */
    warp?: string;
    /** Why a config failed: dns, dns-poisoned, tcp-refused, tcp-timeout, tcp-reset, tls-reset, tls-timeout, tls-cert, proxy-auth, http-status, http-timeout, config… */
    failureKind?: string;
    ttfb?: number;
    connectTime?: number;
    successCount?: number;
    totalCount?: number;
    endpoints?: EndpointResult[];
    endpointSummary?: string;
    protocol?: ProtocolInfo;
    rttMin?: number;
    rttAvg?: number;
    rttMax?: number;
    jitter?: number;
    rttSamples?: number;
    fragment?: string;
}

export interface ScanResult {
    ip: string;
    latency_ms: number;
    download_mbps: number;
    upload_mbps: number;
    error?: string;
    speed_error?: string;
    colo?: string;
    port?: number;
}

export interface GeneralConfig {
    Protocol: string;
    Address: string;
    Port: string;
    ID: string;
    Host: string;
    Network: string;
    Path: string;
    Remark: string;
    TLS: string;
    SNI: string;
    OrigLink: string;
}

export interface ActiveOutbound {
    link: string;
    status: string;
    delay: number;
    download: number;
    upload: number;
    location: string;
    protocol: ProtocolInfo;
}

export type RotationStatus = 'idle' | 'testing' | 'switching' | 'rotating' | 'stalled';

export interface ProxyDetails {
    inbound: GeneralConfig;
    activeOutbound: ActiveOutbound | null;
    rotationStatus: RotationStatus;
    nextRotationTime: string; // ISO 8601
    rotationInterval: number;
    totalConfigs: number;
    chainEnabled: boolean;
    chainHops?: GeneralConfig[];
    chainRotation?: string;
    /** host-tun: the server waits for a confirmation that SSH still works. */
    deadmanPending?: boolean;
}

export interface Progress {
    completed: number;
    total: number;
    /** CF scan only. */
    succeeded?: number;
    failed?: number;
}

// --- DPI finder (pkg/dpi) ---

export interface DpiFragment {
    packets: string;
    length: { min: number; max: number };
    interval: { min: number; max: number };
    noises?: { type: string; packet: string; delay: { min: number; max: number } }[];
}

export interface DpiProfile {
    name: string;
    /** The --fragment value that reproduces this profile ("" = none). */
    spec: string;
    fragment?: DpiFragment | null;
    sni?: string;
    /** CLI flags that reproduce this profile, e.g. "--fragment …" or "--noise …". */
    args?: string;
}

export type DpiResultStatus = 'pass' | 'partial' | 'fail' | 'error' | 'skipped';

export interface DpiResult {
    index: number;
    profile: DpiProfile;
    status: DpiResultStatus;
    attempts: number;
    successes: number;
    delays?: number[];
    minDelay: number;
    medianDelay: number;
    failures?: Record<string, number>;
    lastError?: string;
    link?: string;
}

export interface DpiDirectCheck {
    address: string;
    transport: string;
    checked: boolean;
    tcpOk: boolean;
    tcpDelay: number;
    tcpError?: string;
    tlsChecked: boolean;
    tlsOk: boolean;
    tlsDelay: number;
    tlsError?: string;
    tlsKind?: string;
    sni?: string;
}

export type DpiVerdict = 'no-interference' | 'fragment-helps' | 'partial' | 'server-unreachable' | 'sni-blocked' | 'no-workaround' | 'canceled';

export interface DpiReport {
    link: string;
    protocol: string;
    core: string;
    direct: DpiDirectCheck;
    results: DpiResult[];
    best?: DpiResult | null;
    verdict: DpiVerdict | string;
    advice: string;
    /** Nanoseconds (Go time.Duration). */
    duration: number;
}
