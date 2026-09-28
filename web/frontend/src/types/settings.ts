export interface FragmentRange {
    min: number;
    max: number;
}

export type NoiseType = 'rand' | 'str' | 'base64' | 'hex';

export interface FragmentNoise {
    type: NoiseType;
    /** Length range ("10-20") for rand, the payload otherwise. */
    packet: string;
    delay: FragmentRange;
}

/** Wire form, matching pkg/core/fragment.Options. */
export interface FragmentOptions {
    packets: string;
    length: FragmentRange;
    interval: FragmentRange;
    noises?: FragmentNoise[];
}

/** Form state for the fragment section (superset of the wire form). */
export interface FragmentSettings {
    enabled: boolean;
    packetsMode: 'tlshello' | '1-3' | 'custom';
    customPackets: string;
    length: FragmentRange;
    interval: FragmentRange;
    noises: FragmentNoise[];
}

export interface ProxySettings {
    /** app and host-tun need a server started with --allow-host-modes. */
    mode: 'inbound' | 'system' | 'app' | 'host-tun';
    coreType: 'xray' | 'sing-box';
    listenAddr: string;
    listenPort: string;
    inboundProtocol: 'socks' | 'vless' | 'vmess';
    inboundTransport: 'tcp' | 'ws' | 'grpc' | 'xhttp';
    inboundUUID: string;
    rotationInterval: number;
    maximumAllowedDelay: number;
    batchSize: number;
    concurrency: number;
    healthCheckInterval: number;
    healthFailThreshold: number;
    /** URL fetched through the proxy by health checks ("" = server default). */
    healthCheckUrl: string;
    drainTimeout: number;
    blacklistStrikes: number;
    blacklistDuration: number;
    insecureTLS: boolean;
    enableTls: boolean;
    tlsCertPath: string;
    tlsKeyPath: string;
    tlsSni: string;
    tlsAlpn: string;
    transportOptions: {
        ws: { host: string; path: string; };
        grpc: { serviceName: string; authority: string; };
        xhttp: { mode: string; host: string; path: string; };
    };
    chain: boolean;
    chainLinks: string;
    chainHops: number;
    chainRotation: 'none' | 'exit' | 'full';
    chainAttempts: number;
    /** app/host-tun: block traffic that would bypass the tunnel. */
    killSwitch: boolean;
    /** app mode: named network namespace ("" = automatic). */
    namespaceName: string;
    fragment: FragmentSettings;
}

export type CheckPreset = 'none' | 'cloudflare' | 'gstatic' | 'global' | 'google' | 'streaming' | 'custom';

export interface HttpTesterSettings {
    threadCount: number;
    maxDelay: number;
    timeout: number;
    retries: number;
    coreType: 'auto' | 'xray' | 'singbox';
    destURL: string;
    httpMethod: 'GET' | 'POST';
    checkPreset: CheckPreset;
    customEndpoints: string;
    successThreshold: number;
    insecureTLS: boolean;
    speedtest: boolean;
    doIPInfo: boolean;
    speedtestAmount: number;
    speedtestTimeout: number;
    /** "" = speed.cloudflare.com. */
    speedtestURL: string;
    probeSamples: number;
    saveToDB: boolean;
    prescan: boolean;
    prescanTimeout: number;
    maxPassed: number;
    dedup: boolean;
    /** DB sources only: protocol filter ("" = all) and a cap (0 = no cap). */
    dbProtocol: string;
    dbLimit: number;
    /** Resolver used by failure diagnostics, e.g. https://1.1.1.1/dns-query. */
    resolver: string;
    noDiagnose: boolean;
    fragment: FragmentSettings;
}

export interface CfScannerSettings {
    threadCount: number;
    timeout: number;
    retry: number;
    port: number;
    saveToDB: boolean;
    /** Random IPs per /24 (v4) or /48 (v6); 0 = every address. */
    samplePerSubnet: number;
    /** 0 = server default. */
    maxIPs: number;
    speedtestURL: string;
    doSpeedtest: boolean;
    speedtestOptions: {
        top: number;
        concurrency: number;
        timeout: number;
        downloadMB: number;
        uploadMB: number;
    };
    advancedOptions: {
        configLink: string;
        insecureTLS: boolean;
        shuffleIPs: boolean;
        shuffleSubnets: boolean;
    };
    fragment: FragmentSettings;
}
