import { toast } from "sonner";
import { useAppStore, type TaskStatus } from "@/stores/appStore";
import { type HttpResult, type ProxyDetails, type ProxyStatus } from "@/types/dashboard";

const BATCH_INTERVAL = 250; // ms
const BASE_RECONNECT_DELAY = 1000; // 1 second
const MAX_RECONNECT_DELAY = 30000; // 30 seconds
const MAX_RECONNECT_ATTEMPTS = 50;

// Define the types for our event listeners
type EventCallback = (data: any) => void;
type Listeners = {
    [key: string]: Set<EventCallback>;
};

class WebSocketService {
    private ws: WebSocket | null = null;
    private listeners: Listeners = {}; // Event emitter store
    private httpResultBuffer: HttpResult[] = [];
    private httpResultTimer: number | null = null;
    private reconnectAttempts = 0;
    private reconnectTimer: number | null = null;

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
                    console.error(`Error in WebSocket event listener for '${event}':`, e);
                }
            });
        }
    }

    // Connection Management
    connect() {
        if (this.ws && this.ws.readyState < 2) return;

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this.reconnectAttempts = 0; // Reset on successful connection
            useAppStore.getState().setWsConnected(true);
            this.emit('log', "\x1b[32m[WebSocket] Connection established.\x1b[0m");
            // Send auth token immediately after connection
            const token = useAppStore.getState().token;
            if (token) {
                const authMsg = JSON.stringify({ type: 'auth', token });
                this.ws?.send(authMsg);
            }
        };
        this.ws.onmessage = this.handleMessage.bind(this);
        this.ws.onclose = () => {
            useAppStore.getState().setWsConnected(false);
            this.stopHttpResultBatching();
            this.scheduleReconnect();
        };
        this.ws.onerror = (error) => {
            console.error("WebSocket error:", error);
            this.emit('log', `\x1b[31m[WebSocket] Error: ${(error as Event).type}\x1b[0m`);
            this.ws?.close();
        };
    }

    private scheduleReconnect() {
        if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            this.emit('log', "\x1b[31m[WebSocket] Max reconnection attempts reached. Please refresh the page.\x1b[0m");
            return;
        }

        const delay = Math.min(BASE_RECONNECT_DELAY * Math.pow(2, this.reconnectAttempts), MAX_RECONNECT_DELAY);
        this.reconnectAttempts++;
        this.emit('log', `\x1b[31m[WebSocket] Connection closed. Reconnecting in ${(delay / 1000).toFixed(1)}s (attempt ${this.reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...\x1b[0m`);

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

    private handleMessage(event: MessageEvent) {
        const { setHttpTestStatus, updateScanResults, setScanStatus, setHttpTestProgress, setScanProgress, setProxyDetails, setProxyStatus } = useAppStore.getState();
        const rawData = event.data;
        if (!rawData) return;

        try {
            const message = JSON.parse(rawData);
            switch (message.type) {
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
                        // Capture previous state BEFORE updating, so the toast logic works correctly.
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
                    updateScanResults(message.data);
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
                    this.emit('log', `\x1b[33m[WebSocket] Unhandled message type: ${message.type}\x1b[0m`);
                    console.warn("Unhandled WebSocket message:", message);
                    break;
            }
        } catch (e) {
            console.error("WebSocket received non-JSON message:", rawData, "Error:", e);
            this.emit('log', `\x1b[31m[WebSocket] Received invalid data: ${rawData}\x1b[0m`);
        }
    }

    disconnect() {
        this.stopHttpResultBatching();
        if (this.reconnectTimer !== null) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.reconnectAttempts = MAX_RECONNECT_ATTEMPTS; // Prevent reconnecting after manual disconnect
        this.ws?.close();
    }
}

export const webSocketService = new WebSocketService();