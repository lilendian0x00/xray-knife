import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, DialogClose } from "@/components/ui/dialog";
import { Loader2, RotateCcw, Settings, Play, Square, RefreshCw, Link2 } from "lucide-react";
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

    const isStopped = proxyStatus === 'stopped';
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

    const renderTransportFields = () => {
        const transport = proxySettings.inboundTransport;
        const opts = proxySettings.transportOptions;

        if (transport === 'ws') {
            return (
                <div className="grid grid-cols-2 gap-3">
                    <div className="flex flex-col gap-1.5"><Label htmlFor="ws-path" className="text-xs">WS Path</Label><Input id="ws-path" value={opts.ws.path} onChange={e => handleTransportOptionChange('path', e.target.value)} disabled={!isStopped} /></div>
                    <div className="flex flex-col gap-1.5"><Label htmlFor="ws-host" className="text-xs">WS Host</Label><Input id="ws-host" value={opts.ws.host} onChange={e => handleTransportOptionChange('host', e.target.value)} disabled={!isStopped} /></div>
                </div>
            );
        }
        if (transport === 'grpc') {
            return (
                <div className="grid grid-cols-2 gap-3">
                    <div className="flex flex-col gap-1.5"><Label htmlFor="grpc-service" className="text-xs">Service Name</Label><Input id="grpc-service" value={opts.grpc.serviceName} onChange={e => handleTransportOptionChange('serviceName', e.target.value)} disabled={!isStopped} /></div>
                    <div className="flex flex-col gap-1.5"><Label htmlFor="grpc-authority" className="text-xs">Authority</Label><Input id="grpc-authority" value={opts.grpc.authority} onChange={e => handleTransportOptionChange('authority', e.target.value)} disabled={!isStopped} /></div>
                </div>
            );
        }
        if (transport === 'xhttp') {
            return (
                <div className="grid grid-cols-3 gap-3">
                    <div className="flex flex-col gap-1.5"><Label htmlFor="xhttp-mode" className="text-xs">Mode</Label><Input id="xhttp-mode" value={opts.xhttp.mode} onChange={e => handleTransportOptionChange('mode', e.target.value)} disabled={!isStopped} /></div>
                    <div className="flex flex-col gap-1.5"><Label htmlFor="xhttp-host" className="text-xs">Host</Label><Input id="xhttp-host" value={opts.xhttp.host} onChange={e => handleTransportOptionChange('host', e.target.value)} disabled={!isStopped} /></div>
                    <div className="flex flex-col gap-1.5"><Label htmlFor="xhttp-path" className="text-xs">Path</Label><Input id="xhttp-path" value={opts.xhttp.path} onChange={e => handleTransportOptionChange('path', e.target.value)} disabled={!isStopped} /></div>
                </div>
            );
        }
        return null;
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
            <CardContent className="flex flex-col gap-5">
                {/* Config Links — always visible, primary element */}
                <div className="flex flex-col gap-2">
                    <Label htmlFor="proxy-configs">Configuration Links</Label>
                    <Textarea
                        id="proxy-configs"
                        placeholder={"vmess://...\nvless://...\ntrojan://...\nss://..."}
                        className="h-36 font-mono text-sm resize-y"
                        value={proxyConfigs}
                        onChange={(e) => setProxyConfigs(e.target.value)}
                        disabled={!isStopped}
                    />
                </div>

                {/* Action Buttons */}
                <div className="flex gap-2">
                    <Button onClick={handleStartProxy} disabled={!isStopped} className="flex-1">
                        {proxyStatus === 'starting'
                            ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Starting...</>
                            : <><Play className="mr-2 h-4 w-4" />Start</>
                        }
                    </Button>
                    <Dialog>
                        <DialogTrigger asChild>
                            <Button variant="destructive" disabled={proxyStatus !== 'running'} className="flex-1">
                                {proxyStatus === 'stopping'
                                    ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Stopping...</>
                                    : <><Square className="mr-2 h-4 w-4" />Stop</>
                                }
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
                    <Button onClick={handleRotateProxy} variant="outline" disabled={proxyStatus !== 'running'} size="icon" title="Rotate Now">
                        <RefreshCw className="h-4 w-4" />
                    </Button>
                </div>

                {/* Tabbed Settings */}
                <Tabs defaultValue="general" className="w-full">
                    <TabsList className="w-full">
                        <TabsTrigger value="general">General</TabsTrigger>
                        <TabsTrigger value="inbound" disabled={isSystemMode}>Inbound</TabsTrigger>
                        <TabsTrigger value="rotation">Rotation</TabsTrigger>
                        <TabsTrigger value="chain">Chain</TabsTrigger>
                    </TabsList>

                    {/* General Tab */}
                    <TabsContent value="general" className="space-y-4 pt-2">
                        <div className="grid grid-cols-2 gap-3">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="proxy-mode" className="text-xs">Mode</Label>
                                <Select value={proxySettings.mode} onValueChange={(v) => updateProxySettings({ mode: v as any })} disabled={!isStopped}>
                                    <SelectTrigger id="proxy-mode"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="inbound">Inbound</SelectItem>
                                        <SelectItem value="system">System Proxy</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="core-type-proxy" className="text-xs">Core</Label>
                                <Select value={proxySettings.coreType} onValueChange={(v) => updateProxySettings({ coreType: v as any })} disabled={!isStopped}>
                                    <SelectTrigger id="core-type-proxy"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="xray">Xray</SelectItem>
                                        <SelectItem value="sing-box">Sing-box</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="listen-addr" className="text-xs">Listen Address</Label>
                                <Input id="listen-addr" value={proxySettings.listenAddr} onChange={(e) => updateProxySettings({ listenAddr: e.target.value })} disabled={!isStopped} />
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="listen-port" className="text-xs">Listen Port</Label>
                                <Input id="listen-port" value={proxySettings.listenPort} onChange={(e) => updateProxySettings({ listenPort: e.target.value })} disabled={!isStopped} />
                            </div>
                        </div>
                        <AnimatePresence>
                            {isSystemMode && (
                                <motion.p
                                    className="text-xs text-muted-foreground bg-muted/50 rounded-md p-3"
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                >
                                    System mode creates a local SOCKS proxy and configures your OS to route traffic through it. Protocol, transport, UUID, and TLS settings are managed automatically.
                                </motion.p>
                            )}
                        </AnimatePresence>
                    </TabsContent>

                    {/* Inbound Tab */}
                    <TabsContent value="inbound" className="space-y-4 pt-2">
                        <div className="grid grid-cols-3 gap-3">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="inbound-protocol" className="text-xs">Protocol</Label>
                                <Select value={proxySettings.inboundProtocol} onValueChange={(v) => updateProxySettings({ inboundProtocol: v as any })} disabled={!isStopped}>
                                    <SelectTrigger id="inbound-protocol"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="socks">SOCKS</SelectItem>
                                        <SelectItem value="vless">VLESS</SelectItem>
                                        <SelectItem value="vmess">VMess</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="inbound-transport" className="text-xs">Transport</Label>
                                <Select value={proxySettings.inboundTransport} onValueChange={(v) => updateProxySettings({ inboundTransport: v as any })} disabled={!isStopped || proxySettings.inboundProtocol === 'socks'}>
                                    <SelectTrigger id="inbound-transport"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="tcp">TCP</SelectItem>
                                        <SelectItem value="ws">WebSocket</SelectItem>
                                        <SelectItem value="grpc">gRPC</SelectItem>
                                        <SelectItem value="xhttp">XHTTP</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="inbound-uuid" className="text-xs">UUID</Label>
                                <Input id="inbound-uuid" value={proxySettings.inboundUUID} onChange={(e) => updateProxySettings({ inboundUUID: e.target.value })} disabled={!isStopped} />
                            </div>
                        </div>

                        {/* Transport-specific settings inline */}
                        <AnimatePresence>
                            {showTransportSettings && (
                                <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                    className="overflow-hidden"
                                >
                                    <div className="border rounded-md p-3 space-y-2">
                                        <p className="text-xs font-medium text-muted-foreground">{proxySettings.inboundTransport.toUpperCase()} Transport Options</p>
                                        {renderTransportFields()}
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>

                        {/* TLS Section */}
                        <AnimatePresence>
                            {isTlsCompatible && (
                                <motion.div
                                    className="space-y-3"
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                    transition={{ duration: 0.2 }}
                                >
                                    <div className="flex items-center space-x-2">
                                        <Checkbox
                                            id="enable-tls"
                                            checked={proxySettings.enableTls}
                                            onCheckedChange={(c) => updateProxySettings({ enableTls: Boolean(c) })}
                                            disabled={!isStopped || proxySettings.inboundTransport === 'grpc'}
                                        />
                                        <Label htmlFor="enable-tls" className="text-sm cursor-pointer">
                                            Enable TLS {proxySettings.inboundTransport === 'grpc' && "(Required for gRPC)"}
                                        </Label>
                                    </div>
                                    <AnimatePresence>
                                        {proxySettings.enableTls && (
                                            <motion.div
                                                className="grid grid-cols-2 gap-3 pl-6"
                                                initial={{ opacity: 0, height: 0 }}
                                                animate={{ opacity: 1, height: 'auto' }}
                                                exit={{ opacity: 0, height: 0 }}
                                                transition={{ duration: 0.2 }}
                                            >
                                                <div className="flex flex-col gap-1.5"><Label htmlFor="tls-cert-path" className="text-xs">Cert Path</Label><Input id="tls-cert-path" placeholder="/path/to/cert.pem" value={proxySettings.tlsCertPath} onChange={(e) => updateProxySettings({ tlsCertPath: e.target.value })} disabled={!isStopped} /></div>
                                                <div className="flex flex-col gap-1.5"><Label htmlFor="tls-key-path" className="text-xs">Key Path</Label><Input id="tls-key-path" placeholder="/path/to/key.pem" value={proxySettings.tlsKeyPath} onChange={(e) => updateProxySettings({ tlsKeyPath: e.target.value })} disabled={!isStopped} /></div>
                                                <div className="flex flex-col gap-1.5"><Label htmlFor="tls-sni" className="text-xs">SNI</Label><Input id="tls-sni" placeholder="your.domain.com" value={proxySettings.tlsSni} onChange={(e) => updateProxySettings({ tlsSni: e.target.value })} disabled={!isStopped} /></div>
                                                <div className="flex flex-col gap-1.5"><Label htmlFor="tls-alpn" className="text-xs">ALPN</Label><Input id="tls-alpn" placeholder="h2,http/1.1" value={proxySettings.tlsAlpn} onChange={(e) => updateProxySettings({ tlsAlpn: e.target.value })} disabled={!isStopped} /></div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </TabsContent>

                    {/* Rotation Tab */}
                    <TabsContent value="rotation" className="space-y-4 pt-2">
                        <div className="grid grid-cols-2 gap-3">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="rotation-interval" className="text-xs">Interval (seconds)</Label>
                                <InputNumber id="rotation-interval" min={1} value={proxySettings.rotationInterval} onChange={(v) => updateProxySettings({ rotationInterval: v })} disabled={!isStopped} />
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="max-delay-proxy" className="text-xs">Max Delay (ms)</Label>
                                <InputNumber id="max-delay-proxy" min={100} step={100} value={proxySettings.maximumAllowedDelay} onChange={(v) => updateProxySettings({ maximumAllowedDelay: v })} disabled={!isStopped} />
                            </div>
                        </div>

                        <div className="border rounded-md p-3 space-y-3">
                            <div className="flex items-center gap-2">
                                <Settings className="size-3.5 text-muted-foreground" />
                                <p className="text-xs font-medium text-muted-foreground">Advanced</p>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="batch-size" className="text-xs">Batch Size <span className="text-muted-foreground">(0=auto)</span></Label>
                                    <InputNumber id="batch-size" min={0} value={proxySettings.batchSize} onChange={(v) => updateProxySettings({ batchSize: v })} disabled={!isStopped} />
                                </div>
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="concurrency" className="text-xs">Concurrency <span className="text-muted-foreground">(0=auto)</span></Label>
                                    <InputNumber id="concurrency" min={0} value={proxySettings.concurrency} onChange={(v) => updateProxySettings({ concurrency: v })} disabled={!isStopped} />
                                </div>
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="health-check" className="text-xs">Health Check (s) <span className="text-muted-foreground">(0=off)</span></Label>
                                    <InputNumber id="health-check" min={0} value={proxySettings.healthCheckInterval} onChange={(v) => updateProxySettings({ healthCheckInterval: v })} disabled={!isStopped} />
                                </div>
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="drain-timeout" className="text-xs">Drain Timeout (s)</Label>
                                    <InputNumber id="drain-timeout" min={0} value={proxySettings.drainTimeout} onChange={(v) => updateProxySettings({ drainTimeout: v })} disabled={!isStopped} />
                                </div>
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="blacklist-strikes" className="text-xs">Blacklist Strikes <span className="text-muted-foreground">(0=off)</span></Label>
                                    <InputNumber id="blacklist-strikes" min={0} value={proxySettings.blacklistStrikes} onChange={(v) => updateProxySettings({ blacklistStrikes: v })} disabled={!isStopped} />
                                </div>
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="blacklist-duration" className="text-xs">Blacklist Duration (s)</Label>
                                    <InputNumber id="blacklist-duration" min={0} value={proxySettings.blacklistDuration} onChange={(v) => updateProxySettings({ blacklistDuration: v })} disabled={!isStopped} />
                                </div>
                            </div>
                        </div>
                    </TabsContent>

                    {/* Chain Tab */}
                    <TabsContent value="chain" className="space-y-4 pt-2">
                        <div className="flex items-center space-x-2">
                            <Checkbox
                                id="enable-chain"
                                checked={proxySettings.chain}
                                onCheckedChange={(c) => updateProxySettings({ chain: Boolean(c) })}
                                disabled={!isStopped}
                            />
                            <Label htmlFor="enable-chain" className="cursor-pointer">
                                <div className="flex items-center gap-1.5">
                                    <Link2 className="size-3.5" />
                                    <span className="text-sm">Enable Multi-Hop Chaining</span>
                                </div>
                            </Label>
                        </div>

                        <AnimatePresence>
                            {proxySettings.chain && (
                                <motion.div
                                    className="space-y-3"
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    exit={{ opacity: 0, height: 0 }}
                                    transition={{ duration: 0.2 }}
                                >
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="flex flex-col gap-1.5">
                                            <Label htmlFor="chain-hops" className="text-xs">Number of Hops</Label>
                                            <InputNumber id="chain-hops" min={2} max={10} value={proxySettings.chainHops} onChange={(v) => updateProxySettings({ chainHops: v })} disabled={!isStopped} />
                                        </div>
                                        <div className="flex flex-col gap-1.5">
                                            <Label htmlFor="chain-rotation" className="text-xs">Rotation Mode</Label>
                                            <Select value={proxySettings.chainRotation} onValueChange={(v) => updateProxySettings({ chainRotation: v as any })} disabled={!isStopped}>
                                                <SelectTrigger id="chain-rotation"><SelectValue /></SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="none">None</SelectItem>
                                                    <SelectItem value="exit">Exit Hop Only</SelectItem>
                                                    <SelectItem value="full">Full Chain</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                    </div>
                                    <div className="flex flex-col gap-1.5">
                                        <Label htmlFor="chain-links" className="text-xs">Fixed Chain Links <span className="text-muted-foreground">(optional)</span></Label>
                                        <Textarea
                                            id="chain-links"
                                            placeholder="vmess://hop1|vless://hop2"
                                            className="h-16 font-mono text-sm"
                                            value={proxySettings.chainLinks}
                                            onChange={(e) => updateProxySettings({ chainLinks: e.target.value })}
                                            disabled={!isStopped}
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Pipe-separated links used in order. When provided, hops from the config pool are ignored and rotation is disabled.
                                        </p>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>

                        {!proxySettings.chain && (
                            <p className="text-xs text-muted-foreground bg-muted/50 rounded-md p-3">
                                Enable chaining to route traffic through multiple proxy hops before reaching the destination. Requires an explicit core (Xray or Sing-box).
                            </p>
                        )}
                    </TabsContent>
                </Tabs>
            </CardContent>
        </Card>
    );
}
