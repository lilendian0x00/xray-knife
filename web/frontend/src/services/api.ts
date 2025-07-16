import axios from 'axios';
import { type ProxySettings } from '@/types/settings';
import { type ProxyDetails } from '@/types/dashboard';

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
    async startHttpTest(settings: any, links: string[]) {
        return axios.post('/api/v1/http/test', { ...settings, links });
    },
    async startCfScan(settings: any, subnets: string[], isResuming: boolean) {
        const payload = {
            ...settings,
            Subnets: subnets,
            Resume: isResuming,
            Verbose: true,
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