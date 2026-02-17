export interface ProxySettings {
    mode: 'inbound' | 'system';
    coreType: 'xray' | 'sing-box';
    listenAddr: string;
    listenPort: string;
    inboundProtocol: 'socks' | 'vless' | 'vmess';
    inboundTransport: 'tcp' | 'ws' | 'grpc' | 'xhttp';
    inboundUUID: string;
    rotationInterval: number;
    maximumAllowedDelay: number;
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
}

export interface HttpTesterSettings {
    threadCount: number;
    maxDelay: number;
    coreType: 'auto' | 'xray' | 'singbox';
    destURL: string;
    httpMethod: 'GET' | 'POST';
    insecureTLS: boolean;
    speedtest: boolean;
    doIPInfo: boolean;
    speedtestAmount: number;
}

export interface CfScannerSettings {
    threadCount: number;
    timeout: number;
    retry: number;
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
}