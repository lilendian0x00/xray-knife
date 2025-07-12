import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import axios from 'axios';
import { type ProxyStatus } from "../Dashboard";

interface ProxyTabProps {
    status: ProxyStatus;
    setStatus: React.Dispatch<React.SetStateAction<ProxyStatus>>;
}

export function ProxyTab({ status, setStatus }: ProxyTabProps) {
    const [proxyConfigs, setProxyConfigs] = useState('');

    const handleStartProxy = async () => {
        if (!proxyConfigs.trim()) {
            toast.error("Proxy configurations cannot be empty.");
            return;
        }
        setStatus('starting');
        toast.info("Starting proxy service...");

        try {
            const links = proxyConfigs.trim().split('\n');
            await axios.post('/api/v1/proxy/start', {
                CoreType: "auto",
                ConfigLinks: links,
                ListenAddr: "127.0.0.1",
                ListenPort: "9999",
                InboundProtocol: "socks",
                RotationInterval: 300,
                MaximumAllowedDelay: 3000,
                Verbose: true,
            });
            setStatus('running');
            toast.success("Proxy service started successfully.");
        } catch (error) {
            console.error("Failed to start proxy:", error);
            toast.error("Failed to start proxy service. Check logs for details.");
            setStatus('stopped');
        }
    };

    const handleStopProxy = async () => {
        setStatus('stopping');
        toast.info("Stopping proxy service...");
        try {
            await axios.post('/api/v1/proxy/stop');
            setStatus('stopped');
            toast.success("Proxy service stopped.");
        } catch (error) {
            console.error("Failed to stop proxy:", error);
            toast.error("Failed to stop proxy service.");
            setStatus('running'); // Revert status
        }
    };

    const handleRotateProxy = async () => {
        toast.info("Sending rotate signal...");
        try {
            await axios.post('/api/v1/proxy/rotate');
            toast.success("Rotate signal sent.");
        } catch (error) {
            console.error("Failed to rotate proxy:", error);
            toast.error("Failed to send rotate signal.");
        }
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle>Proxy Service</CardTitle>
                <CardDescription>Manage the local proxy service. Enter one or more configuration links below.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
                <div className="flex items-center gap-2">
                    <Label>SOCKS5 Listener</Label>
                    <Input value="127.0.0.1:9999" disabled className="w-40" />
                </div>
                <Label htmlFor="proxy-configs">Configuration Links</Label>
                <Textarea
                    id="proxy-configs"
                    placeholder="vless://...
trojan://...
ss://..."
                    className="h-40 font-mono text-sm"
                    value={proxyConfigs}
                    onChange={(e) => setProxyConfigs(e.target.value)}
                    disabled={status === 'running'}
                />
                <div className="flex gap-4 flex-col sm:flex-row">
                    <Button onClick={handleStartProxy} disabled={status !== 'stopped'}>
                        {status === 'starting' ? 'Starting...' : 'Start Proxy'}
                    </Button>
                    <Button onClick={handleStopProxy} variant="destructive" disabled={status !== 'running'}>
                        {status === 'stopping' ? 'Stopping...' : 'Stop Proxy'}
                    </Button>
                    <Button onClick={handleRotateProxy} variant="secondary" disabled={status !== 'running'}>
                        Rotate Now
                    </Button>
                </div>
            </CardContent>
        </Card>
    );
}