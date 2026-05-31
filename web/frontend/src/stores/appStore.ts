import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { type ProxySettings, type HttpTesterSettings, type CfScannerSettings, type MITMDFSettings } from '@/types/settings';
import { type HttpResult, type ProxyStatus, type ProxyDetails, type ScanResult } from '@/types/dashboard';

// Default States
const defaultProxySettings: ProxySettings = {
    mode: 'inbound', coreType: 'xray', listenAddr: '127.0.0.1', listenPort: '9999', inboundProtocol: 'socks',
    inboundTransport: 'tcp', inboundUUID: 'random', rotationInterval: 300, maximumAllowedDelay: 3000,
    batchSize: 0, concurrency: 0, healthCheckInterval: 30, drainTimeout: 0,
    blacklistStrikes: 3, blacklistDuration: 600,
    enableTls: false, tlsCertPath: '', tlsKeyPath: '', tlsSni: '', tlsAlpn: '',
    transportOptions: { ws: { host: '', path: '/' }, grpc: { serviceName: 'grpc-service', authority: '' }, xhttp: { mode: 'auto', host: '', path: '/' } },
    chain: false, chainLinks: '', chainHops: 2, chainRotation: 'none'
};
const defaultHttpSettings: HttpTesterSettings = {
    threadCount: 50, maxDelay: 5000, coreType: 'auto', destURL: 'https://cloudflare.com/cdn-cgi/trace',
    httpMethod: 'GET', insecureTLS: false, speedtest: false, doIPInfo: true, speedtestAmount: 10000,
};
const defaultCfScannerSettings: CfScannerSettings = {
    threadCount: 100, timeout: 5000, retry: 1, doSpeedtest: false,
    speedtestOptions: { top: 10, concurrency: 4, timeout: 30, downloadMB: 10, uploadMB: 5 },
    advancedOptions: { configLink: '', insecureTLS: false, shuffleIPs: false, shuffleSubnets: false }
};
const defaultMITMDFSettings: MITMDFSettings = {
    certPath: 'mycert.crt', keyPath: 'mycert.key', listenPort: 10808, socks5Port: 10808,
    groups: [
        { name: 'google', enabled: true, frontDomain: 'www.google.com', extraDomains: ['googlevideo.com', 'youtube.com', 'dns.google'] },
        { name: 'meta', enabled: true, frontDomain: 'www.microsoft.com', extraDomains: ['instagram.com', 'facebook.com', 'whatsapp.com', 'fb.com', 'meta.com'] },
        { name: 'fastly', enabled: true, frontDomain: 'github.githubassets.com', extraDomains: ['reddit.com', 'fastly.com', 'github.com', 'cnn.com', 'buzzfeed.com'] },
        { name: 'dns', enabled: true, frontDomain: 'www.microsoft.com', extraDomains: [] },
    ],
    extraIRDomains: [],
};

// --- Progress State ---
interface ProgressState { completed: number; total: number; }
const initialProgress: ProgressState = { completed: 0, total: 0 };

// --- Store Interfaces ---
export type TaskStatus = 'idle' | 'starting' | 'running' | 'stopping' | 'finished';

interface AppState {
    proxySettings: ProxySettings;
    httpSettings: HttpTesterSettings;
    cfScannerSettings: CfScannerSettings;
    mitmdfSettings: MITMDFSettings;
    mitmdfStatus: 'stopped' | 'running' | 'starting' | 'stopping' | 'error';
    proxyStatus: ProxyStatus;
    scanStatus: TaskStatus;
    httpTestStatus: TaskStatus;
    httpResults: HttpResult[];
    scanResults: ScanResult[];
    proxyDetails: ProxyDetails | null;
    httpTestProgress: ProgressState;
    scanProgress: ProgressState;
    token: string | null;
    isAuthenticated: boolean;
    authRequired: boolean | null; // null = not yet checked
    sseConnected: boolean;
}

interface AppActions {
    updateProxySettings: (settings: Partial<ProxySettings>) => void;
    updateHttpSettings: (settings: Partial<HttpTesterSettings>) => void;
    updateCfScannerSettings: (settings: Partial<CfScannerSettings>) => void;
    updateMITMDFSettings: (settings: Partial<MITMDFSettings>) => void;
    resetProxySettings: () => void;
    resetHttpSettings: () => void;
    resetCfScannerSettings: () => void;
    resetMITMDFSettings: () => void;
    setMITMDFStatus: (status: 'stopped' | 'running' | 'starting' | 'stopping' | 'error') => void;
    setProxyStatus: (status: ProxyStatus) => void;
    setScanStatus: (status: TaskStatus) => void;
    setHttpTestStatus: (status: TaskStatus) => void;
    addHttpResultsBatch: (results: HttpResult[]) => void;
    clearHttpResults: () => void;
    setHttpResults: (results: HttpResult[]) => void;
    updateScanResults: (result: ScanResult) => void;
    setScanResults: (results: ScanResult[]) => void;
    clearScanResults: () => void;
    setProxyDetails: (details: ProxyDetails | null) => void;
    setHttpTestProgress: (progress: ProgressState) => void;
    setScanProgress: (progress: ProgressState) => void;
    setToken: (token: string | null) => void;
    setAuthRequired: (required: boolean) => void;
    logout: () => void;
    setSseConnected: (connected: boolean) => void;
}

export const useAppStore = create<AppState & AppActions>()(
    persist(
        (set) => ({
            proxySettings: defaultProxySettings,
            httpSettings: defaultHttpSettings,
            cfScannerSettings: defaultCfScannerSettings,
            mitmdfSettings: defaultMITMDFSettings,
            mitmdfStatus: 'stopped',
            proxyStatus: 'stopped',
            scanStatus: 'idle',
            httpTestStatus: 'idle',
            httpResults: [],
            scanResults: [],
            proxyDetails: null,
            httpTestProgress: initialProgress,
            scanProgress: initialProgress,
            token: null,
            isAuthenticated: false,
            authRequired: null,
            sseConnected: false,

            updateProxySettings: (newSettings) => set(state => ({ proxySettings: { ...state.proxySettings, ...newSettings } })),
            updateHttpSettings: (newSettings) => set(state => ({ httpSettings: { ...state.httpSettings, ...newSettings } })),
            updateCfScannerSettings: (newSettings) => set(state => ({ cfScannerSettings: { ...state.cfScannerSettings, ...newSettings } })),
            updateMITMDFSettings: (newSettings) => set(state => ({ mitmdfSettings: { ...state.mitmdfSettings, ...newSettings } })),
            resetProxySettings: () => set({ proxySettings: defaultProxySettings }),
            resetHttpSettings: () => set({ httpSettings: defaultHttpSettings }),
            resetCfScannerSettings: () => set({ cfScannerSettings: defaultCfScannerSettings }),
            resetMITMDFSettings: () => set({ mitmdfSettings: defaultMITMDFSettings }),
            setMITMDFStatus: (status) => set({ mitmdfStatus: status }),
            setProxyStatus: (status) => set({ proxyStatus: status }),
            setScanStatus: (status) => set({ 
                scanStatus: status,
                ...((status === 'idle' || status === 'starting') && { scanProgress: initialProgress })
            }),
            setHttpTestStatus: (status) => set({
                httpTestStatus: status,
                ...((status === 'idle' || status === 'starting') && { httpTestProgress: initialProgress })
            }),
            addHttpResultsBatch: (results) => set(state => ({ httpResults: [...state.httpResults, ...results] })),
            clearHttpResults: () => set({ httpResults: [] }),
            setHttpResults: (results) => set({ httpResults: results }),
            updateScanResults: (result) => set(state => ({ scanResults: [...state.scanResults.filter(r => r.ip !== result.ip), result] })),
            setScanResults: (results) => set({ scanResults: results }),
            clearScanResults: () => set({ scanResults: [] }),
            setProxyDetails: (details) => set({ proxyDetails: details }),
            setHttpTestProgress: (progress) => set({ httpTestProgress: progress }),
            setScanProgress: (progress) => set({ scanProgress: progress }),
            setToken: (token) => set({ token, isAuthenticated: !!token }),
            setAuthRequired: (required) => set({ authRequired: required }),
            logout: () => set({ token: null, isAuthenticated: false }),
            setSseConnected: (connected) => set({ sseConnected: connected }),
        }),
        {
            name: 'xray-knife-app-storage',
            storage: createJSONStorage(() => localStorage),
            partialize: (state) => ({
                proxySettings: state.proxySettings,
                httpSettings: state.httpSettings,
                cfScannerSettings: state.cfScannerSettings,
                mitmdfSettings: state.mitmdfSettings,
                token: state.token,
            }),
            merge: (persistedState, currentState) => {
                const persisted = persistedState as Partial<AppState & AppActions> | undefined;
                const persistedGroups = persisted?.mitmdfSettings?.groups;
                const groups = Array.isArray(persistedGroups) ? persistedGroups : defaultMITMDFSettings.groups;
                return {
                    ...currentState,
                    ...persisted,
                    proxySettings: { ...defaultProxySettings, ...persisted?.proxySettings },
                    httpSettings: { ...defaultHttpSettings, ...persisted?.httpSettings },
                    cfScannerSettings: { ...defaultCfScannerSettings, ...persisted?.cfScannerSettings },
                    mitmdfSettings: { ...defaultMITMDFSettings, ...persisted?.mitmdfSettings, groups },
                };
            },
            onRehydrateStorage: () => (state) => {
                if (state && state.token) {
                    // Decode JWT payload and check expiry
                    try {
                        const payload = JSON.parse(atob(state.token.split('.')[1]));
                        if (payload.exp && payload.exp * 1000 < Date.now()) {
                            // Token expired, clear it
                            state.token = null;
                            state.isAuthenticated = false;
                            return;
                        }
                    } catch {
                        // Malformed token, clear it
                        state.token = null;
                        state.isAuthenticated = false;
                        return;
                    }
                    state.isAuthenticated = true;
                } else if (state) {
                    state.isAuthenticated = false;
                }
            },
        }
    )
);