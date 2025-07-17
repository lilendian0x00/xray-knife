import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { type ProxySettings, type HttpTesterSettings, type CfScannerSettings } from '@/types/settings';
import { type HttpResult } from '@/types/dashboard';
import { type ScanResult, type ScanStatus } from '@/pages/dashboard/CFScannerTab';
import { type ProxyStatus, type ProxyDetails } from '@/types/dashboard';

// --- Default States ---
const defaultProxySettings: ProxySettings = {
    coreType: 'xray', listenAddr: '127.0.0.1', listenPort: '9999', inboundProtocol: 'socks',
    inboundTransport: 'tcp', inboundUUID: 'random', rotationInterval: 300, maximumAllowedDelay: 3000,
    enableTls: false, tlsCertPath: '', tlsKeyPath: '', tlsSni: '', tlsAlpn: '',
    transportOptions: { ws: { host: '', path: '/' }, grpc: { serviceName: 'grpc-service', authority: '' }, xhttp: { mode: 'auto', host: '', path: '/' } }
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

// --- Store Interfaces ---
interface AppState {
    // Persisted Settings
    proxySettings: ProxySettings;
    httpSettings: HttpTesterSettings;
    cfScannerSettings: CfScannerSettings;
    // Transient State
    proxyStatus: ProxyStatus;
    scanStatus: ScanStatus;
    httpTestStatus: 'idle' | 'testing' | 'stopping';
    httpResults: HttpResult[];
    scanResults: ScanResult[];
    proxyDetails: ProxyDetails | null;
}

interface AppActions {
    // Setters for settings
    updateProxySettings: (settings: Partial<ProxySettings>) => void;
    updateHttpSettings: (settings: Partial<HttpTesterSettings>) => void;
    updateCfScannerSettings: (settings: Partial<CfScannerSettings>) => void;
    resetProxySettings: () => void;
    resetHttpSettings: () => void;
    resetCfScannerSettings: () => void;
    // Setters for transient state
    setProxyStatus: (status: ProxyStatus) => void;
    setScanStatus: (status: ScanStatus) => void;
    setHttpTestStatus: (status: 'idle' | 'testing' | 'stopping') => void;
    addHttpResultsBatch: (results: HttpResult[]) => void;
    clearHttpResults: () => void;
    setHttpResults: (results: HttpResult[]) => void;
    updateScanResults: (result: ScanResult) => void;
    setScanResults: (results: ScanResult[]) => void;
    clearScanResults: () => void;
    setProxyDetails: (details: ProxyDetails | null) => void;
}

// --- Zustand Store ---
export const useAppStore = create<AppState & AppActions>()(
    persist(
        (set) => ({
            // --- Persisted State ---
            proxySettings: defaultProxySettings,
            httpSettings: defaultHttpSettings,
            cfScannerSettings: defaultCfScannerSettings,
            // --- Transient State ---
            proxyStatus: 'stopped',
            scanStatus: 'idle',
            httpTestStatus: 'idle',
            httpResults: [],
            scanResults: [],
            proxyDetails: null,
            // --- Actions ---
            updateProxySettings: (newSettings) => set(state => ({ proxySettings: { ...state.proxySettings, ...newSettings } })),
            updateHttpSettings: (newSettings) => set(state => ({ httpSettings: { ...state.httpSettings, ...newSettings } })),
            updateCfScannerSettings: (newSettings) => set(state => ({ cfScannerSettings: { ...state.cfScannerSettings, ...newSettings } })),
            resetProxySettings: () => set({ proxySettings: defaultProxySettings }),
            resetHttpSettings: () => set({ httpSettings: defaultHttpSettings }),
            resetCfScannerSettings: () => set({ cfScannerSettings: defaultCfScannerSettings }),
            setProxyStatus: (status) => set({ proxyStatus: status }),
            setScanStatus: (status) => set({ scanStatus: status }),
            setHttpTestStatus: (status) => set({ httpTestStatus: status }),
            addHttpResultsBatch: (results) => set(state => ({ httpResults: [...state.httpResults, ...results] })),
            clearHttpResults: () => set({ httpResults: [] }),
            setHttpResults: (results) => set({ httpResults: results }),
            updateScanResults: (result) => set(state => ({ scanResults: [...state.scanResults.filter(r => r.ip !== result.ip), result] })),
            setScanResults: (results) => set({ scanResults: results }),
            clearScanResults: () => set({ scanResults: [] }),
            setProxyDetails: (details) => set({ proxyDetails: details }),
        }),
        {
            name: 'xray-knife-app-storage', // name of the item in the storage (must be unique)
            storage: createJSONStorage(() => localStorage), // (optional) by default, 'localStorage' is used
            partialize: (state) => ({ 
                proxySettings: state.proxySettings,
                httpSettings: state.httpSettings,
                cfScannerSettings: state.cfScannerSettings
            }), // Only persist the settings
        }
    )
);