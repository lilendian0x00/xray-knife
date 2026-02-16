import axios from 'axios';
import { toast } from "sonner";
import { type ProxySettings, type HttpTesterSettings, type CfScannerSettings } from '@/types/settings';
import { type ProxyDetails, type HttpResult } from '@/types/dashboard';
import { useAppStore } from '@/stores/appStore';

export const api = {
    // Auth Endpoints
    checkAuth() {
        return axios.get<{ auth_required: boolean }>('/api/v1/auth/check');
    },
    login(username: string, password: string) {
        return axios.post('/api/v1/login', { username, password });
    },

    // Proxy Endpoints
    startProxy(settings: ProxySettings, links: string[]) {
        const payload = {
            ...settings,
            ConfigLinks: links,
            InboundTransport: settings.inboundProtocol === 'socks' ? '' : settings.inboundTransport,
            Verbose: true,
            wsPath: settings.inboundTransport === 'ws' ? settings.transportOptions.ws.path : '',
            wsHost: settings.inboundTransport === 'ws' ? settings.transportOptions.ws.host : '',
            grpcServiceName: settings.inboundTransport === 'grpc' ? settings.transportOptions.grpc.serviceName : '',
            grpcAuthority: settings.inboundTransport === 'grpc' ? settings.transportOptions.grpc.authority : '',
            xhttpMode: settings.inboundTransport === 'xhttp' ? settings.transportOptions.xhttp.mode : '',
            xhttpHost: settings.inboundTransport === 'xhttp' ? settings.transportOptions.xhttp.host : '',
            xhttpPath: settings.inboundTransport === 'xhttp' ? settings.transportOptions.xhttp.path : '',
        };
        return axios.post('/api/v1/proxy/start', payload);
    },
    stopProxy() { return axios.post('/api/v1/proxy/stop'); },
    rotateProxy() { return axios.post('/api/v1/proxy/rotate'); },
    getProxyStatus() { return axios.get<{ status: string }>('/api/v1/proxy/status'); },
    getProxyDetails() { return axios.get<ProxyDetails>('/api/v1/proxy/details'); },
    
    // HTTP Tester Endpoints
    startHttpTest(settings: HttpTesterSettings, links: string[]) {
        const { coreType, ...rest } = settings;
        return axios.post('/api/v1/http/test', {
            ...rest,
            core: coreType,
            links,
            verbose: false,
        });
    },
    stopHttpTest() { return axios.post('/api/v1/http/test/stop'); },
    getHttpTestStatus() { return axios.get<{ status: 'idle' | 'testing' | 'stopping' }>('/api/v1/http/test/status'); },
    getHttpTestHistory() { return axios.get<HttpResult[]>('/api/v1/http/test/history'); },
    clearHttpTestHistory() { return axios.post('/api/v1/http/test/clear_history'); },

    // CF Scanner Endpoints
    getCfScannerRanges() { return axios.get<{ ranges: string[] }>('/api/v1/scanner/cf/ranges'); },
    getCfScannerStatus() { return axios.get<{ is_scanning: boolean }>('/api/v1/scanner/cf/status'); },
    getCfScannerHistory() { return axios.get('/api/v1/scanner/cf/history'); },
    startCfScan(settings: CfScannerSettings, subnets: string[], isResuming: boolean) {
        const payload = {
            threadCount: settings.threadCount,
            timeout: settings.timeout,
            retry: settings.retry,
            doSpeedtest: settings.doSpeedtest,
            speedtestTop: settings.speedtestOptions.top,
            speedtestConcurrency: settings.speedtestOptions.concurrency,
            speedtestTimeout: settings.speedtestOptions.timeout,
            downloadMB: settings.speedtestOptions.downloadMB,
            uploadMB: settings.speedtestOptions.uploadMB,
            configLink: settings.advancedOptions.configLink,
            insecureTLS: settings.advancedOptions.insecureTLS,
            shuffleIPs: settings.advancedOptions.shuffleIPs,
            shuffleSubnets: settings.advancedOptions.shuffleSubnets,
            subnets: subnets,
            resume: isResuming,
            verbose: false,
        };
        return axios.post('/api/v1/scanner/cf/start', payload);
    },
    stopCfScan() { return axios.post('/api/v1/scanner/cf/stop'); },
    clearCfScanHistory() { return axios.post('/api/v1/scanner/cf/clear_history'); },
};

// AXIOS INTERCEPTORS
axios.interceptors.request.use(config => {
    const token = useAppStore.getState().token;
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
}, error => {
    return Promise.reject(error);
});

axios.interceptors.response.use(response => response, error => {
    if (error.response && error.response.status === 401) {
        if (useAppStore.getState().isAuthenticated) {
            useAppStore.getState().logout();
            toast.error("Session expired. Please log in again.");
        }
    }
    return Promise.reject(error);
});