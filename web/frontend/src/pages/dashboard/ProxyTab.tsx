import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import axios from 'axios';
import { type ProxyStatus } from "../Dashboard";

interface ProxyTabProps {
    status: ProxyStatus;
    setStatus: React.Dispatch<React.SetStateAction<ProxyStatus>>;
}

export function ProxyTab({ status, setStatus }: ProxyTabProps) {
    const [coreType, setCoreType] = useState('xray');
    const [listenAddr, setListenAddr] = useState('127.0.0.1');
    const [listenPort, setListenPort] = useState('9999');
    const [inboundProtocol, setInboundProtocol] = useState('socks');
    const [rotationInterval, setRotationInterval] = useState(300);
    const [maximumAllowedDelay, setMaximumAllowedDelay] = useState(3000);
    const [proxyConfigs, setProxyConfigs] = useState('');

    const handleStartProxy = async () => {
        if (!proxyConfigs.trim()) {
            toast.error("Proxy configurations cannot be empty.");
            return;
        }
        setStatus("starting");
        toast.info("Starting proxy service...");

        try {
            const links = proxyConfigs.trim().split('\n');
            await axios.post('/api/v1/proxy/start', {
                CoreType: coreType,
                ConfigLinks: links,
                ListenAddr: listenAddr,
                ListenPort: listenPort,
                InboundProtocol: inboundProtocol,
                RotationInterval: rotationInterval,
                MaximumAllowedDelay: maximumAllowedDelay,
                Verbose: true,
            });
            setStatus("running");
            toast.success("Proxy service started successfully.");
        } catch (err) {
            let errorMessage = "An unknown error occurred.";
            if (axios.isAxiosError(err) && err.response) {
                errorMessage = err.response.data.error || err.message;
            } else if (err instanceof Error) {
                errorMessage = err.message;
            }
            console.error("Failed to start proxy:", err);
            toast.error(`Failed to start proxy: ${errorMessage}`);
            setStatus("stopped");
        }
    };

    const handleStopProxy = async () => {
        setStatus("stopping");
        toast.info("Stopping proxy service...");
        try {
            await axios.post('/api/v1/proxy/stop');
            setStatus("stopped");
            toast.success("Proxy service stopped.");
        } catch (error) {
            console.error("Failed to stop proxy:", error);
            toast.error("Failed to stop proxy service.");
            setStatus("running"); // Revert status
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
            <CardContent className="flex flex-col gap-6">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="core-type-proxy">Core Type</Label>
                        <Select value={coreType} onValueChange={setCoreType} disabled={status !== 'stopped'}>
                            <SelectTrigger id="core-type-proxy">
                                <SelectValue placeholder="Select core" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="xray">Xray</SelectItem>
                                <SelectItem value="sing-box">Sing-box</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="inbound-protocol">Inbound</Label>
                        <Select value={inboundProtocol} onValueChange={setInboundProtocol} disabled={status !== 'stopped'}>
                            <SelectTrigger id="inbound-protocol">
                                <SelectValue placeholder="Select inbound" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="socks">SOCKS</SelectItem>
                                <SelectItem value="vless">VLESS (TCP)</SelectItem>
                                <SelectItem value="vmess">VMess (TCP)</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="listen-port">Listen Port</Label>
                        <Input id="listen-port" value={listenPort} onChange={(e) => setListenPort(e.target.value)} disabled={status !== 'stopped'} />
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="rotation-interval">Rotation Interval (s)</Label>
                        <Input id="rotation-interval" type="number" value={rotationInterval} onChange={(e) => setRotationInterval(Number(e.target.value))} disabled={status !== 'stopped'} />
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="max-delay-proxy">Max Delay (ms)</Label>
                        <Input id="max-delay-proxy" type="number" value={maximumAllowedDelay} onChange={(e) => setMaximumAllowedDelay(Number(e.target.value))} disabled={status !== 'stopped'} />
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="listen-addr">Listen Address</Label>
                        <Input id="listen-addr" value={listenAddr} onChange={(e) => setListenAddr(e.target.value)} disabled={status !== 'stopped'} />
                    </div>
                </div>
                <div className="flex flex-col gap-3">
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
                </div>

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