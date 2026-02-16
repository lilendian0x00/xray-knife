import { toast } from "sonner";
import { useAppStore, type TaskStatus } from "@/stores/appStore";
import { type HttpResult, type ProxyDetails, type ProxyStatus, type ScanResult } from "@/types/dashboard";

const BATCH_INTERVAL = 250; // ms
const BASE_RECONNECT_DELAY = 1000; // 1 second
const MAX_RECONNECT_DELAY = 30000; // 30 seconds
const MAX_RECONNECT_ATTEMPTS = 50;

// Define the types for our event listeners
type EventCallback = (data: any) => void;
type Listeners = {
    [key: string]: Set<EventCallback>;
};

class SSEService {
    private eventSource: EventSource | null = null;
    private listeners: Listeners = {}; // Event emitter store
    private httpResultBuffer: HttpResult[] = [];
    private httpResultTimer: number | null = null;
    private reconnectAttempts = 0;
    private reconnectTimer: number | null = null;
    private isManualDisconnect = false;

    // --- Event Emitter Methods ---
    on(event: string, callback: EventCallback) {
        if (!this.listeners[event]) {
            this.listeners[event] = new Set();
        }
        this.listeners[event].add(callback);
    }

    off(event: string, callback: EventCallback) {
        if (this.listeners[event]) {
            this.listeners[event].delete(callback);
        }
    }

    private emit(event: string, data: any) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => {
                try {
                    callback(data);
                } catch (e) {
                    console.error(`Error in SSE event listener for '${event}':`, e);
                }
            });
        }
    }

    // Connection Management
    connect() {
        if (this.eventSource && this.eventSource.readyState !== EventSource.CLOSED) return;

        this.isManualDisconnect = false;
        const eventSource = new EventSource("/events");
        this.eventSource = eventSource;

        eventSource.onopen = () => {
            this.reconnectAttempts = 0;
            useAppStore.getState().setSseConnected(true);
            this.emit('log', "\x1b[32m[SSE] Connection established.\x1b[0m");
        };

        eventSource.onerror = () => {
            useAppStore.getState().setSseConnected(false);
            this.stopHttpResultBatching();
            eventSource.close();
            this.eventSource = null;
            if (!this.isManualDisconnect) {
                this.scheduleReconnect();
            }
        };

        // Register handlers for all event types
        eventSource.addEventListener('log', (e) => this.handleEvent('log', e));
        eventSource.addEventListener('proxy_status', (e) => this.handleEvent('proxy_status', e));
        eventSource.addEventListener('proxy_details', (e) => this.handleEvent('proxy_details', e));
        eventSource.addEventListener('http_result', (e) => this.handleEvent('http_result', e));
        eventSource.addEventListener('http_test_status', (e) => this.handleEvent('http_test_status', e));
        eventSource.addEventListener('cfscan_result', (e) => this.handleEvent('cfscan_result', e));
        eventSource.addEventListener('cfscan_status', (e) => this.handleEvent('cfscan_status', e));
        eventSource.addEventListener('http_test_progress', (e) => this.handleEvent('http_test_progress', e));
        eventSource.addEventListener('cf_scan_progress', (e) => this.handleEvent('cf_scan_progress', e));
    }

    private handleEvent(type: string, event: MessageEvent) {
        try {
            const message = JSON.parse(event.data);
            this.processMessage(type, message);
        } catch (e) {
            console.error("SSE received non-JSON data:", event.data, "Error:", e);
            this.emit('log', `\x1b[31m[SSE] Received invalid data: ${event.data}\x1b[0m`);
        }
    }

    private processMessage(type: string, message: any) {
        const { setHttpTestStatus, updateScanResults, setScanStatus, setHttpTestProgress, setScanProgress, setProxyDetails, setProxyStatus } = useAppStore.getState();

        switch (type) {
            case 'log':
                this.emit('log', message.data);
                break;

            case 'proxy_status': {
                const proxyStatus = message.data as ProxyStatus;
                const wasStopping = useAppStore.getState().proxyStatus === 'stopping';

                setProxyStatus(proxyStatus);

                if (proxyStatus === 'stopped') {
                    setProxyDetails(null);
                    if (message.error) {
                        toast.error("Proxy stopped due to an error.", { description: message.error });
                    } else if (wasStopping) {
                        // Suppress success toast if user manually stopped it
                    }
                }
                break;
            }

            case 'proxy_details':
                setProxyDetails(message.data as ProxyDetails);
                break;
            case 'http_result':
                this.startHttpResultBatching();
                this.httpResultBuffer.push(message.data);
                break;
            case 'http_test_status': {
                this.stopHttpResultBatching();
                const status = message.data as 'finished' | 'stopped' | 'running';
                if (status === 'finished' || status === 'stopped') {
                    const previousStatus = useAppStore.getState().httpTestStatus;
                    setHttpTestStatus('idle');
                    if (previousStatus !== 'stopping') {
                        toast.success(status === 'finished' ? "HTTP test finished." : "HTTP test stopped.");
                    }
                } else {
                    setHttpTestStatus(status as TaskStatus);
                }
                break;
            }
            case 'cfscan_result':
                updateScanResults(message.data as ScanResult);
                break;
            case 'cfscan_status': {
                const status = message.data as 'finished' | 'error' | 'running' | 'stopped';
                if (status === 'finished' || status === 'error' || status === 'stopped') {
                    setScanStatus('idle');
                    if (status === 'finished') toast.success("Cloudflare scan finished.");
                    else if (status === 'error') toast.error(`Scan failed: ${message.message || 'Unknown error'}`);
                } else {
                    setScanStatus(status as TaskStatus);
                }
                break;
            }
            case 'http_test_progress':
                setHttpTestProgress(message.data);
                break;
            case 'cf_scan_progress':
                setScanProgress(message.data);
                break;
            default:
                this.emit('log', `\x1b[33m[SSE] Unhandled message type: ${type}\x1b[0m`);
                console.warn("Unhandled SSE message:", type, message);
                break;
        }
    }

    private scheduleReconnect() {
        if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            this.emit('log', "\x1b[31m[SSE] Max reconnection attempts reached. Please refresh the page.\x1b[0m");
            return;
        }

        const delay = Math.min(BASE_RECONNECT_DELAY * Math.pow(2, this.reconnectAttempts), MAX_RECONNECT_DELAY);
        this.reconnectAttempts++;
        this.emit('log', `\x1b[31m[SSE] Connection closed. Reconnecting in ${(delay / 1000).toFixed(1)}s (attempt ${this.reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...\x1b[0m`);

        this.reconnectTimer = window.setTimeout(() => this.connect(), delay);
    }

    private flushHttpResultBuffer() {
        if (this.httpResultBuffer.length > 0) {
            useAppStore.getState().addHttpResultsBatch(this.httpResultBuffer);
            this.httpResultBuffer = [];
        }
    }

    private startHttpResultBatching() {
        if (this.httpResultTimer === null) {
            this.httpResultTimer = window.setInterval(() => {
                this.flushHttpResultBuffer();
            }, BATCH_INTERVAL);
        }
    }

    private stopHttpResultBatching() {
        if (this.httpResultTimer !== null) {
            clearInterval(this.httpResultTimer);
            this.httpResultTimer = null;
        }
        this.flushHttpResultBuffer();
    }

    disconnect() {
        this.isManualDisconnect = true;
        this.stopHttpResultBatching();
        if (this.reconnectTimer !== null) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.reconnectAttempts = 0;
        this.eventSource?.close();
        this.eventSource = null;
    }
}

export const sseService = new SSEService();
