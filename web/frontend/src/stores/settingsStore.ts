import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { ProxySettings, HttpTesterSettings, CfScannerSettings } from '@/types/settings';
import { defaultFragment } from '@/lib/fragment';

export const defaultProxySettings: ProxySettings = {
    mode: 'inbound', coreType: 'xray', listenAddr: '127.0.0.1', listenPort: '9999', inboundProtocol: 'socks',
    inboundTransport: 'tcp', inboundUUID: 'random', rotationInterval: 300, maximumAllowedDelay: 3000,
    batchSize: 0, concurrency: 0, healthCheckInterval: 30, healthFailThreshold: 0, healthCheckUrl: '', drainTimeout: 0,
    blacklistStrikes: 3, blacklistDuration: 600, insecureTLS: false,
    enableTls: false, tlsCertPath: '', tlsKeyPath: '', tlsSni: '', tlsAlpn: '',
    transportOptions: { ws: { host: '', path: '/' }, grpc: { serviceName: 'grpc-service', authority: '' }, xhttp: { mode: 'auto', host: '', path: '/' } },
    chain: false, chainLinks: '', chainHops: 2, chainRotation: 'none', chainAttempts: 0, killSwitch: false, namespaceName: '',
    fragment: defaultFragment,
};

export const defaultHttpSettings: HttpTesterSettings = {
    threadCount: 50, maxDelay: 5000, timeout: 0, retries: 0, coreType: 'auto',
    destURL: 'https://cloudflare.com/cdn-cgi/trace', httpMethod: 'GET',
    checkPreset: 'none', customEndpoints: '', successThreshold: 0,
    insecureTLS: false, speedtest: false, doIPInfo: true, speedtestAmount: 10000, speedtestTimeout: 0, speedtestURL: '',
    probeSamples: 1, saveToDB: false, prescan: false, prescanTimeout: 0, maxPassed: 0, dedup: true, dbProtocol: '', dbLimit: 0, resolver: '', noDiagnose: false,
    fragment: defaultFragment,
};

export const defaultCfScannerSettings: CfScannerSettings = {
    threadCount: 100, timeout: 5000, retry: 1, port: 443, saveToDB: false, samplePerSubnet: 0, maxIPs: 0, speedtestURL: '', doSpeedtest: false,
    speedtestOptions: { top: 10, concurrency: 4, timeout: 30, downloadMB: 10, uploadMB: 5 },
    advancedOptions: { configLink: '', insecureTLS: false, shuffleIPs: false, shuffleSubnets: false },
    fragment: defaultFragment,
};

interface SettingsState {
    proxySettings: ProxySettings;
    httpSettings: HttpTesterSettings;
    cfScannerSettings: CfScannerSettings;
    updateProxySettings: (s: Partial<ProxySettings>) => void;
    updateHttpSettings: (s: Partial<HttpTesterSettings>) => void;
    updateCfScannerSettings: (s: Partial<CfScannerSettings>) => void;
    resetProxySettings: () => void;
    resetHttpSettings: () => void;
    resetCfScannerSettings: () => void;
}

// Deep-ish merge so settings saved by an older build pick up new nested defaults.
function mergeDefaults<T extends object>(defaults: T, saved: Partial<T> | undefined): T {
    if (!saved || typeof saved !== 'object') return defaults;
    const out = { ...defaults } as Record<string, unknown>;
    for (const [k, v] of Object.entries(saved)) {
        if (!(k in defaults)) continue;
        const d = (defaults as Record<string, unknown>)[k];
        if (d && typeof d === 'object' && !Array.isArray(d) && v && typeof v === 'object' && !Array.isArray(v)) {
            out[k] = mergeDefaults(d as object, v as object);
        } else if (v !== undefined && v !== null && typeof v === typeof d) {
            out[k] = v;
        }
    }
    return out as T;
}

export const useSettingsStore = create<SettingsState>()(
    persist(
        (set) => ({
            proxySettings: defaultProxySettings,
            httpSettings: defaultHttpSettings,
            cfScannerSettings: defaultCfScannerSettings,
            updateProxySettings: (s) => set((st) => ({ proxySettings: { ...st.proxySettings, ...s } })),
            updateHttpSettings: (s) => set((st) => ({ httpSettings: { ...st.httpSettings, ...s } })),
            updateCfScannerSettings: (s) => set((st) => ({ cfScannerSettings: { ...st.cfScannerSettings, ...s } })),
            resetProxySettings: () => set({ proxySettings: defaultProxySettings }),
            resetHttpSettings: () => set({ httpSettings: defaultHttpSettings }),
            resetCfScannerSettings: () => set({ cfScannerSettings: defaultCfScannerSettings }),
        }),
        {
            // Same key as the previous single store, so existing settings carry over.
            name: 'xray-knife-app-storage',
            storage: createJSONStorage(() => localStorage),
            partialize: (s) => ({ proxySettings: s.proxySettings, httpSettings: s.httpSettings, cfScannerSettings: s.cfScannerSettings }),
            merge: (persisted, current) => {
                const p = persisted as Partial<SettingsState> | undefined;
                return {
                    ...current,
                    proxySettings: mergeDefaults(defaultProxySettings, p?.proxySettings),
                    httpSettings: mergeDefaults(defaultHttpSettings, p?.httpSettings),
                    cfScannerSettings: mergeDefaults(defaultCfScannerSettings, p?.cfScannerSettings),
                };
            },
        }
    )
);
