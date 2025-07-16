import { toast } from "sonner";
import { useAppStore } from "@/stores/appStore";

class WebSocketService {
    private ws: WebSocket | null = null;
    private term: { writeln: (text: string) => void } | null = null;

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
            setTimeout(() => this.connect(terminal), 3000);
        };
        this.ws.onerror = (error) => {
            console.error("WebSocket error:", error);
            this.term?.writeln(`\x1b[31m[WebSocket] Error: ${(error as Event).type}\x1b[0m`);
            this.ws?.close();
        };
    }

    private handleMessage(event: MessageEvent) {
        try {
            const message = JSON.parse(event.data);
            const { setState } = useAppStore;

            switch (message.type) {
                case 'http_result':
                    setState(state => ({ httpResults: [...state.httpResults, message.data] }));
                    break;
                case 'cfscan_result':
                    setState(state => ({ scanResults: [...state.scanResults.filter(r => r.ip !== message.data.ip), message.data] }));
                    break;
                case 'cfscan_status':
                    if (message.data === 'finished' || message.data === 'error') {
                        setState({ scanStatus: 'idle' });
                        if (message.data === 'finished') {
                            toast.success("Cloudflare scan finished.");
                        } else {
                            toast.error(`Scan failed: ${message.message || 'Unknown error'}`);
                        }
                    }
                    break;
                default:
                    this.term?.writeln(`[RAW JSON] ${event.data.trimEnd()}`);
                    break;
            }
        } catch (e) {
            this.term?.writeln(event.data.trimEnd());
        }
    }

    disconnect() {
        this.ws?.close();
    }
}

export const webSocketService = new WebSocketService();