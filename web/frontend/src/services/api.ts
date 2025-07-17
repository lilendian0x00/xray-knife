import axios from 'axios';
import { type ProxySettings, type HttpTesterSettings, type CfScannerSettings } from '@/types/settings';
import { type ProxyDetails, type HttpResult } from '@/types/dashboard';

export const api = {
    async startProxy(settings: ProxySettings, links: string[]) {
        const payload = {
            ...settings,
            ConfigLinks: links,
            InboundTransport: settings.inboundProtocol === 'socks' ? '' : settings.inboundTransport,
            Verbose: true,
            // Flatten transport options
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
    async stopProxy() {
        return axios.post('/api/v1/proxy/stop');
    },
    async rotateProxy() {
        return axios.post('/api/v1/proxy/rotate');
    },
    async getProxyDetails() {
        return axios.get<ProxyDetails>('/api/v1/proxy/details');
    },
    async startHttpTest(settings: HttpTesterSettings, links: string[]) {
        const { coreType, ...rest } = settings;
        return axios.post('/api/v1/http/test', {
            ...rest,
            core: coreType, // Rename frontend's 'coreType' to backend's 'core'
            links,
            verbose: true, // Ensure verbose logging is enabled for Web UI
        });
    },
    async stopHttpTest() {
        return axios.post('/api/v1/http/test/stop');
    },
    async getHttpTestStatus() {
        return axios.get<{ status: 'idle' | 'testing' | 'stopping' }>('/api/v1/http/test/status');
    },
    async getHttpTestHistory() {
        return axios.get<HttpResult[]>('/api/v1/http/test/history');
    },
    async clearHttpTestHistory() {
        return axios.post('/api/v1/http/test/clear_history');
    },
    async startCfScan(settings: CfScannerSettings, subnets: string[], isResuming: boolean) {
        const payload = {
            // Map frontend state to the flat structure the backend expects
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
            verbose: true, // Ensure verbose logging for Web UI
        };
        return axios.post('/api/v1/scanner/cf/start', payload);
    },
    async stopCfScan() {
        return axios.post('/api/v1/scanner/cf/stop');
    },
    async clearCfScanHistory() {
        return axios.post('/api/v1/scanner/cf/clear_history');
    },
};