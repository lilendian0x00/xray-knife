// src/types/dashboard.ts
export type ProxyStatus = 'stopped' | 'running' | 'starting' | 'stopping';

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

export interface ProtocolInfo {
    remark: string;
    protocol: string;
    address: string;
    port: string;
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

export interface ProxyDetails {
    inbound: GeneralConfig;
    activeOutbound: ActiveOutbound | null;
    rotationStatus: 'idle' | 'testing' | 'switching' | 'stalled';
    nextRotationTime: string; // ISO 8601 date string
    rotationInterval: number;
    totalConfigs: number;
}