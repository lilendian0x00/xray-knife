import { toast } from "sonner";
import { useAppStore } from "@/stores/appStore";
import { type HttpResult } from "@/types/dashboard";

const BATCH_INTERVAL = 250; // ms

class WebSocketService {
    private ws: WebSocket | null = null;
    private term: { writeln: (text: string) => void } | null = null;
    private httpResultBuffer: HttpResult[] = [];
    private httpResultTimer: number | null = null;

    connect(terminal: { writeln: (text: string) => void }) {
        this.term = terminal;
        if (this.ws && this.ws.readyState < 2) return;

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => this.term?.writeln("\x1b[32m[WebSocket] Connection established.\x1b[0m");
        this.ws.onmessage = this.handleMessage.bind(this);
        this.ws.onclose = () => {
            this.term?.writeln("\x1b[31m[WebSocket] Connection closed. Retrying in 3 seconds...\x1b[0m");
            this.stopHttpResultBatching();
            setTimeout(() => this.connect(terminal), 3000);
        };
        this.ws.onerror = (error) => {
            console.error("WebSocket error:", error);
            this.term?.writeln(`\x1b[31m[WebSocket] Error: ${(error as Event).type}\x1b[0m`);
            this.ws?.close();
        };
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
        // Final flush to ensure no results are missed
        this.flushHttpResultBuffer();
    }

    private handleMessage(event: MessageEvent) {
        const rawData = event.data;
        if (!rawData) return;

        try {
            const message = JSON.parse(rawData);

            switch (message.type) {
                case 'log':
                    this.term?.writeln(message.data);
                    break;
                case 'http_result':
                    this.startHttpResultBatching();
                    this.httpResultBuffer.push(message.data);
                    break;
                case 'http_test_status':
                    this.stopHttpResultBatching();
                    if (message.data === 'finished' || message.data === 'stopped') {
                        useAppStore.getState().setHttpTestStatus('idle');
                        
                        if (message.data === 'finished') {
                            toast.success("HTTP test finished.");
                        } else {
                            toast.info("HTTP test stopped.");
                        }
                    }
                    break;
                case 'cfscan_result':
                    useAppStore.getState().updateScanResults(message.data);
                    break;
                case 'cfscan_status':
                    if (message.data === 'finished' || message.data === 'error') {
                        useAppStore.getState().setScanStatus('idle');
                        if (message.data === 'finished') {
                            toast.success("Cloudflare scan finished.");
                        } else {
                            toast.error(`Scan failed: ${message.message || 'Unknown error'}`);
                        }
                    }
                    break;
                default:
                    this.term?.writeln(`\x1b[33m[WebSocket] Unhandled message type: ${message.type}\x1b[0m`);
                    console.warn("Unhandled WebSocket message:", message);
                    break;
            }
        } catch (e) {
            console.error("WebSocket received non-JSON message:", rawData, "Error:", e);
            this.term?.writeln(`\x1b[31m[WebSocket] Received invalid data: ${rawData}\x1b[0m`);
        }
    }

    disconnect() {
        this.stopHttpResultBatching();
        this.ws?.close();
    }
}

export const webSocketService = new WebSocketService();