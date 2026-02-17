import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, DialogClose } from "@/components/ui/dialog";
import { Loader2, RotateCcw, Settings } from "lucide-react";
import { useAppStore } from "@/stores/appStore";
import { api } from "@/services/api";
import { usePersistentState } from "@/hooks/usePersistentState";

export function ProxyTab() {
    const {
        proxySettings,
        updateProxySettings,
        resetProxySettings,
        proxyStatus,
        setProxyStatus,
        setProxyDetails
    } = useAppStore();

    const [proxyConfigs, setProxyConfigs] = usePersistentState('proxy-configs-input', '');

    const isSystemMode = proxySettings.mode === 'system';
    const isTlsCompatible = !isSystemMode && (proxySettings.inboundProtocol === 'vless' || proxySettings.inboundProtocol === 'vmess');
    const showTransportSettings = isTlsCompatible && ['ws', 'grpc', 'xhttp'].includes(proxySettings.inboundTransport);

    useEffect(() => {
        if (proxySettings.inboundTransport === 'grpc' && isTlsCompatible) {
            updateProxySettings({ enableTls: true });
        }
    }, [proxySettings.inboundTransport, isTlsCompatible, updateProxySettings]);


    const handleStartProxy = async () => {
        if (!proxyConfigs.trim()) { toast.error("Proxy configurations cannot be empty."); return; }
        if (!isSystemMode && proxySettings.enableTls && (!proxySettings.tlsCertPath.trim() || !proxySettings.tlsKeyPath.trim())) {
            toast.error("TLS Certificate and Key paths are required when TLS is enabled.");
            return;
        }
        setProxyStatus("starting");
        const toastId = toast.loading("Starting proxy service...");

        try {
            await api.startProxy(proxySettings, proxyConfigs.trim().split('\n'));
            setProxyStatus("running");
            toast.success("Proxy service started successfully.", { id: toastId });
            const res = await api.getProxyDetails();
            setProxyDetails(res.data);
        } catch (err: any) {
            const errorMessage = err.response?.data?.error || err.message || "An unknown error occurred.";
            toast.error(`Failed to start proxy: ${errorMessage}`, { id: toastId });
            setProxyStatus("stopped");
        }
    };

    const handleStopProxy = async () => {
        setProxyStatus("stopping");
        const toastId = toast.loading("Stopping proxy service...");

        try {
            await api.stopProxy();

            toast.success("Proxy service stopped.", { id: toastId });
            setProxyStatus("stopped");

        } catch (err: any) {
            toast.error("Failed to stop proxy service.", { id: toastId });
            setProxyStatus("running");
        }
    };

    const handleRotateProxy = async () => {
        toast.info("Sending rotate signal...");
        try {
            await api.rotateProxy();
            toast.success("Rotate signal sent.");
        } catch (err: any) {
            toast.error("Failed to send rotate signal.");
        }
    };

    const handleTransportOptionChange = (field: string, value: string) => {
        const transportKey = proxySettings.inboundTransport as keyof typeof proxySettings.transportOptions;
        updateProxySettings({
            transportOptions: {
                ...proxySettings.transportOptions,
                [transportKey]: {
                    ...proxySettings.transportOptions[transportKey],
                    [field]: value
                }
            }
        });
    };

    const renderTransportSettingsDialog = () => {
        const transport = proxySettings.inboundTransport;
        const opts = proxySettings.transportOptions;

        let content = null;
        if (transport === 'ws') {
            content = <>
                <div className="flex flex-col gap-2"><Label htmlFor="ws-path">Path</Label><Input id="ws-path" value={opts.ws.path} onChange={e => handleTransportOptionChange('path', e.target.value)} /></div>
                <div className="flex flex-col gap-2"><Label htmlFor="ws-host">Host</Label><Input id="ws-host" value={opts.ws.host} onChange={e => handleTransportOptionChange('host', e.target.value)} /></div>
            </>;
        } else if (transport === 'grpc') {
            content = <>
                <div className="flex flex-col gap-2"><Label htmlFor="grpc-service">Service Name</Label><Input id="grpc-service" value={opts.grpc.serviceName} onChange={e => handleTransportOptionChange('serviceName', e.target.value)} /></div>
                <div className="flex flex-col gap-2"><Label htmlFor="grpc-authority">Authority</Label><Input id="grpc-authority" value={opts.grpc.authority} onChange={e => handleTransportOptionChange('authority', e.target.value)} /></div>
            </>;
        } else if (transport === 'xhttp') {
            content = <>
                <div className="flex flex-col gap-2"><Label htmlFor="xhttp-mode">Mode</Label><Input id="xhttp-mode" value={opts.xhttp.mode} onChange={e => handleTransportOptionChange('mode', e.target.value)} /></div>
                <div className="flex flex-col gap-2"><Label htmlFor="xhttp-host">Host</Label><Input id="xhttp-host" value={opts.xhttp.host} onChange={e => handleTransportOptionChange('host', e.target.value)} /></div>
                <div className="flex flex-col gap-2"><Label htmlFor="xhttp-path">Path</Label><Input id="xhttp-path" value={opts.xhttp.path} onChange={e => handleTransportOptionChange('path', e.target.value)} /></div>
            </>;
        }

        return (
            <Dialog>
                <DialogTrigger asChild><Button variant="outline" className="w-full justify-start"><Settings className="mr-2 size-4" /> Configure {proxySettings.inboundTransport.toUpperCase()} Transport</Button></DialogTrigger>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{transport.toUpperCase()} Transport Settings</DialogTitle>
                        <DialogDescription>Configure options specific to the {transport} transport.</DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">{content}</div>
                </DialogContent>
            </Dialog>
        );
    };

    return (
        <Card>
            <CardHeader>
                <div className="flex flex-row gap-2 justify-between items-start">
                    <div className="flex flex-col">
                        <CardTitle>Proxy Service</CardTitle>
                        <CardDescription>Manage the local proxy service.</CardDescription>
                    </div>
                    <Dialog>
                        <DialogTrigger asChild><Button variant="ghost" size="icon" className="shrink-0"><RotateCcw className="size-4" /></Button></DialogTrigger>
                        <DialogContent>
                            <DialogHeader><DialogTitle>Reset Settings</DialogTitle><DialogDescription>Are you sure you want to reset all proxy settings to their defaults?</DialogDescription></DialogHeader>
                            <DialogFooter>
                                <DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose>
                                <DialogClose asChild><Button variant="destructive" onClick={resetProxySettings}>Reset</Button></DialogClose>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                </div>
            </CardHeader>
            <CardContent className="flex flex-col gap-6">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="sm:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-2">
                        <div className="flex flex-col gap-2"><Label htmlFor="proxy-mode">Mode</Label><Select value={proxySettings.mode} onValueChange={(v) => updateProxySettings({ mode: v as any })} disabled={proxyStatus !== 'stopped'}><SelectTrigger id="proxy-mode"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="inbound">Inbound</SelectItem><SelectItem value="system">System Proxy</SelectItem></SelectContent></Select></div>
                        <div className="flex flex-col gap-2"><Label htmlFor="core-type-proxy">Core</Label><Select value={proxySettings.coreType} onValueChange={(v) => updateProxySettings({ coreType: v as any })} disabled={proxyStatus !== 'stopped'}><SelectTrigger id="core-type-proxy"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="xray">Xray</SelectItem><SelectItem value="sing-box">Sing-box</SelectItem></SelectContent></Select></div>
                    </div>

                    <AnimatePresence>
                        {isSystemMode && (
                            <motion.p
                                className="sm:col-span-2 text-sm text-muted-foreground"
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                            >
                                System mode creates a local SOCKS proxy and configures your OS to route traffic through it. Protocol, transport, UUID, and TLS settings are managed automatically.
                            </motion.p>
                        )}
                    </AnimatePresence>

                    <AnimatePresence>
                        {!isSystemMode && (
                            <motion.div
                                className="sm:col-span-2 grid grid-cols-1 sm:grid-cols-3 gap-2"
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                            >
                                <div className="flex flex-col gap-2"><Label htmlFor="inbound-protocol">Protocol</Label><Select value={proxySettings.inboundProtocol} onValueChange={(v) => updateProxySettings({ inboundProtocol: v as any })} disabled={proxyStatus !== 'stopped'}><SelectTrigger id="inbound-protocol"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="socks">SOCKS</SelectItem><SelectItem value="vless">VLESS</SelectItem><SelectItem value="vmess">VMess</SelectItem></SelectContent></Select></div>
                                <div className="flex flex-col gap-2"><Label htmlFor="inbound-transport">Transport</Label><Select value={proxySettings.inboundTransport} onValueChange={(v) => updateProxySettings({ inboundTransport: v as any })} disabled={proxyStatus !== 'stopped' || proxySettings.inboundProtocol === 'socks'}><SelectTrigger id="inbound-transport"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="tcp">TCP</SelectItem><SelectItem value="ws">WebSocket</SelectItem><SelectItem value="grpc">gRPC</SelectItem><SelectItem value="xhttp">XHTTP</SelectItem></SelectContent></Select></div>
                                <div className="flex flex-col gap-2"><Label htmlFor="inbound-uuid">Inbound UUID</Label><Input id="inbound-uuid" value={proxySettings.inboundUUID} onChange={(e) => updateProxySettings({ inboundUUID: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                            </motion.div>
                        )}
                    </AnimatePresence>

                    <AnimatePresence>
                        {showTransportSettings && (
                            <motion.div className="sm:col-span-2" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
                                {renderTransportSettingsDialog()}
                            </motion.div>
                        )}
                    </AnimatePresence>

                    <div className="flex flex-col gap-2"><Label htmlFor="listen-addr">Listen Address</Label><Input id="listen-addr" value={proxySettings.listenAddr} onChange={(e) => updateProxySettings({ listenAddr: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                    <div className="flex flex-col gap-2"><Label htmlFor="listen-port">Listen Port</Label><Input id="listen-port" value={proxySettings.listenPort} onChange={(e) => updateProxySettings({ listenPort: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                    <div className="flex flex-col gap-2"><Label htmlFor="rotation-interval">Rotation Interval (s)</Label><InputNumber id="rotation-interval" min={1} value={proxySettings.rotationInterval} onChange={(v) => updateProxySettings({ rotationInterval: v })} disabled={proxyStatus !== 'stopped'} /></div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="max-delay-proxy">Max Delay (ms)</Label>
                        <InputNumber id="max-delay-proxy" min={100} step={100} value={proxySettings.maximumAllowedDelay} onChange={(v) => updateProxySettings({ maximumAllowedDelay: v })} disabled={proxyStatus !== 'stopped'} />
                    </div>

                    <AnimatePresence>
                        {isTlsCompatible && (
                            <motion.div
                                className="sm:col-span-2 space-y-4 pt-4 border-t"
                                initial={{ opacity: 0, height: 0, paddingTop: 0, borderTopWidth: 0 }}
                                animate={{ opacity: 1, height: 'auto', paddingTop: '1rem', borderTopWidth: '1px' }}
                                exit={{ opacity: 0, height: 0, paddingTop: 0, borderTopWidth: 0 }}
                                transition={{ duration: 0.3 }}
                            >
                                <div className="flex items-center space-x-2"><Checkbox id="enable-tls" checked={proxySettings.enableTls} onCheckedChange={(c) => updateProxySettings({ enableTls: Boolean(c) })} disabled={proxyStatus !== 'stopped' || proxySettings.inboundTransport === 'grpc'} /><Label htmlFor="enable-tls" className="font-medium cursor-pointer">Enable Inbound TLS {proxySettings.inboundTransport === 'grpc' && "(Required)"}</Label></div>
                                <AnimatePresence>
                                    {proxySettings.enableTls && (
                                        <motion.div
                                            className="grid grid-cols-1 sm:grid-cols-2 gap-4"
                                            initial={{ opacity: 0, height: 0 }}
                                            animate={{ opacity: 1, height: 'auto' }}
                                            exit={{ opacity: 0, height: 0 }}
                                            transition={{ duration: 0.2, delay: 0.1 }}
                                        >
                                            <div className="flex flex-col gap-2"><Label htmlFor="tls-cert-path">TLS Cert Path</Label><Input id="tls-cert-path" placeholder="/path/to/cert.pem" value={proxySettings.tlsCertPath} onChange={(e) => updateProxySettings({ tlsCertPath: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                                            <div className="flex flex-col gap-2"><Label htmlFor="tls-key-path">TLS Key Path</Label><Input id="tls-key-path" placeholder="/path/to/key.pem" value={proxySettings.tlsKeyPath} onChange={(e) => updateProxySettings({ tlsKeyPath: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                                            <div className="flex flex-col gap-2"><Label htmlFor="tls-sni">SNI (Server Name)</Label><Input id="tls-sni" placeholder="your.domain.com" value={proxySettings.tlsSni} onChange={(e) => updateProxySettings({ tlsSni: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                                            <div className="flex flex-col gap-2"><Label htmlFor="tls-alpn">ALPN</Label><Input id="tls-alpn" placeholder="h2,http/1.1" value={proxySettings.tlsAlpn} onChange={(e) => updateProxySettings({ tlsAlpn: e.target.value })} disabled={proxyStatus !== 'stopped'} /></div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
                <div className="flex flex-col gap-3"><Label htmlFor="proxy-configs">Configuration Links</Label>
                    <Textarea id="proxy-configs" placeholder="vmess://...
vless://...
trojan://...
ss://..." className="h-40 font-mono text-sm" value={proxyConfigs} onChange={(e) => setProxyConfigs(e.target.value)} disabled={proxyStatus !== 'stopped'} />
                </div>
                <div className="flex gap-4 flex-col sm:flex-row">
                    <Button onClick={handleStartProxy} disabled={proxyStatus !== 'stopped'}>
                        {proxyStatus === 'starting' && <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Starting...</>}
                        {proxyStatus !== 'starting' && 'Start Proxy'}
                    </Button>
                    <Dialog>
                        <DialogTrigger asChild>
                            <Button variant="destructive" disabled={proxyStatus !== 'running'}>
                                {proxyStatus === 'stopping' && <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Stopping...</>}
                                {proxyStatus !== 'stopping' && 'Stop Proxy'}
                            </Button>
                        </DialogTrigger>
                        <DialogContent>
                            <DialogHeader>
                                <DialogTitle>Stop Proxy Service</DialogTitle>
                                <DialogDescription>Are you sure you want to stop the proxy? Active connections will be terminated.</DialogDescription>
                            </DialogHeader>
                            <DialogFooter>
                                <DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose>
                                <DialogClose asChild><Button variant="destructive" onClick={handleStopProxy}>Stop</Button></DialogClose>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                    <Button onClick={handleRotateProxy} variant="secondary" disabled={proxyStatus !== 'running'}>Rotate Now</Button>
                </div>
            </CardContent>
        </Card>
    );
}