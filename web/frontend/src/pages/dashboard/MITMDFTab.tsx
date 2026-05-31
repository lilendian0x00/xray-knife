import { useEffect, useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, DialogClose } from "@/components/ui/dialog";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { Loader2, Play, Square, ShieldCheck, ShieldX, Globe, Settings, Plus, Trash2, Download, CheckCircle2, Search, XCircle } from "lucide-react";
import { useAppStore } from "@/stores/appStore";
import { api } from "@/services/api";
import { usePersistentState } from "@/hooks/usePersistentState";
import type { MITMDFGroupConfig, MITMDFProbeResult } from "@/types/settings";

const defaultGroup = (name: string): MITMDFGroupConfig => ({
    name, enabled: true, frontDomain: 'www.example.com', extraDomains: [],
});

const defaultProbeDomains = [
    'www.google.com',
    'www.microsoft.com',
    'github.githubassets.com',
    'www.cloudflare.com',
    'cloudflare.net',
    'www.akamai.com',
    'www.cloudfront.net',
    'www.fastly.com',
    'www.jsdelivr.net',
    'www.bootstrapcdn.com',
];

export function MITMDFTab() {
    const {
        mitmdfSettings, updateMITMDFSettings, resetMITMDFSettings,
        mitmdfStatus, setMITMDFStatus,
    } = useAppStore();
    const [certChecked, setCertChecked] = useState(false);
    const [certExists, setCertExists] = useState(false);
    const [checkingCert, setCheckingCert] = useState(false);
    const [generatingCert, setGeneratingCert] = useState(false);
    const [installingCert, setInstallingCert] = useState(false);
    const [installMsg, setInstallMsg] = useState('');
    const [assetsReady, setAssetsReady] = useState(false);
    const [checkingAssets, setCheckingAssets] = useState(true);
    const [downloadingAssets, setDownloadingAssets] = useState(false);
    const [extraIRText, setExtraIRText] = usePersistentState('mitmdf-extra-ir', '');
    const [probeDomainsText, setProbeDomainsText] = usePersistentState('mitmdf-probe-domains', defaultProbeDomains.join('\n'));
    const [probeTarget, setProbeTarget] = useState('');
    const [probing, setProbing] = useState(false);
    const [probeResults, setProbeResults] = useState<MITMDFProbeResult[] | null>(null);

    const isStopped = mitmdfStatus === 'stopped';

    useEffect(() => {
        checkCert();
        checkAssets();
    }, []);

    const checkAssets = async () => {
        setCheckingAssets(true);
        try {
            const res = await api.checkMITMDFAssets();
            setAssetsReady(res.data.geosite && res.data.geoip);
        } catch { setAssetsReady(false); }
        setCheckingAssets(false);
    };

    const downloadAssets = async () => {
        setDownloadingAssets(true);
        const toastId = toast.loading("Downloading asset files (geosite.dat + geoip.dat)...");
        try {
            await api.downloadMITMDFAssets();
            toast.success("Assets downloaded.", { id: toastId });
            await checkAssets();
        } catch (err: any) {
            toast.error(`Download failed: ${err.response?.data?.error || err.message}`, { id: toastId });
        }
        setDownloadingAssets(false);
    };

    const checkCert = async () => {
        setCheckingCert(true);
        try {
            const res = await api.checkMITMDFCert(mitmdfSettings.certPath, mitmdfSettings.keyPath);
            setCertExists(res.data.exists);
        } catch { setCertExists(false); }
        setCheckingCert(false);
        setCertChecked(true);
    };

    const generateCert = async () => {
        setGeneratingCert(true);
        try {
            await api.generateMITMDFCert(mitmdfSettings.certPath, mitmdfSettings.keyPath, true);
            toast.success("Self-signed certificate generated.");
            await checkCert();
        } catch (err: any) {
            toast.error(`Failed: ${err.response?.data?.error || err.message}`);
        }
        setGeneratingCert(false);
    };

    const handleDownloadCert = async () => {
        try {
            const res = await api.downloadMITMDFCert(mitmdfSettings.certPath);
            const blob = res.data;
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mitmdf-root-ca.crt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            toast.success("Certificate downloaded.");
        } catch (err: any) {
            toast.error(`Download failed: ${err.response?.data?.error || err.message}`);
        }
    };

    const handleInstallCert = async () => {
        setInstallingCert(true);
        setInstallMsg('');
        try {
            const res = await api.installMITMDFCert(mitmdfSettings.certPath);
            const data = res.data;
            if (data.success) {
                toast.success(data.message);
            } else {
                setInstallMsg(data.message + (data.command ? `\nCommand: ${data.command}` : ''));
                toast.error(data.message);
            }
        } catch (err: any) {
            const msg = err.response?.data?.error || err.message;
            setInstallMsg(msg);
            toast.error(`Install failed: ${msg}`);
        }
        setInstallingCert(false);
    };

    const updateGroup = (idx: number, val: Partial<MITMDFGroupConfig>) => {
        const groups = mitmdfSettings.groups.map((g, i) => i === idx ? { ...g, ...val } : g);
        updateMITMDFSettings({ groups });
    };

    const removeGroup = (idx: number) => {
        const groups = mitmdfSettings.groups.filter((_, i) => i !== idx);
        updateMITMDFSettings({ groups });
    };

    const addGroup = () => {
        const name = 'group-' + (mitmdfSettings.groups.length + 1);
        updateMITMDFSettings({ groups: [...mitmdfSettings.groups, defaultGroup(name)] });
    };

    const addTargetToGroup = (frontDomain: string) => {
        const idx = mitmdfSettings.groups.findIndex(g => g.frontDomain === frontDomain && g.enabled);
        if (idx === -1) {
            toast.error(`No enabled group with front domain "${frontDomain}"`);
            return;
        }
        const group = mitmdfSettings.groups[idx];
        if (group.extraDomains.includes(probeTarget)) {
            toast.info(`"${probeTarget}" is already in group "${group.name}"`);
            return;
        }
        const updated = { ...group, extraDomains: [...group.extraDomains, probeTarget] };
        const groups = mitmdfSettings.groups.map((g, i) => i === idx ? updated : g);
        updateMITMDFSettings({ groups });
        toast.success(`"${probeTarget}" added to group "${group.name}"`);
    };

    const handleProbe = async () => {
        if (!probeTarget.trim()) { toast.error("Enter a target domain to probe."); return; }
        const probeDomains = probeDomainsText.split('\n').map(s => s.trim()).filter(Boolean);
        const configFrontDomains = mitmdfSettings.groups
            .filter(g => g.enabled && g.frontDomain)
            .map(g => g.frontDomain);
        const allDomains = [...new Set([...probeDomains, ...configFrontDomains])];
        if (allDomains.length === 0) { toast.error("No front domains to probe against."); return; }

        setProbing(true);
        setProbeResults(null);
        try {
            const res = await api.probeMITMDFDomain(probeTarget.trim(), allDomains);
            setProbeResults(res.data.results);
        } catch (err: any) {
            toast.error(`Probe failed: ${err.response?.data?.error || err.message}`);
        }
        setProbing(false);
    };

    const handleStart = async () => {
        if (!assetsReady) { toast.error("Download geosite/geoip assets first."); return; }
        if (!certExists) { toast.error("Generate a self-signed certificate first."); return; }
        if (!mitmdfSettings.groups.some(g => g.enabled)) { toast.error("Enable at least one service group."); return; }

        setMITMDFStatus('starting');
        const toastId = toast.loading("Starting MITM-DF service...");
        const payload = {
            ...mitmdfSettings,
            extraIRDomains: extraIRText.split('\n').map(s => s.trim()).filter(Boolean),
        };
        try {
            await api.startMITMDF(payload as any);
            setMITMDFStatus('running');
            toast.success("MITM-DF service started.", { id: toastId });
        } catch (err: any) {
            toast.error(`Failed: ${err.response?.data?.error || err.message}`, { id: toastId });
            setMITMDFStatus('stopped');
        }
    };

    const handleStop = async () => {
        setMITMDFStatus('stopping');
        const toastId = toast.loading("Stopping MITM-DF service...");
        try {
            await api.stopMITMDF();
            toast.success("Stopped.", { id: toastId });
            setMITMDFStatus('stopped');
        } catch (err: any) {
            toast.error("Failed to stop.", { id: toastId });
            setMITMDFStatus('running');
        }
    };

    const statusBadge = () => {
        const colors: Record<string, string> = { running: 'bg-green-500', stopped: 'bg-destructive', starting: 'bg-yellow-500', stopping: 'bg-yellow-500', error: 'bg-destructive' };
        return <Badge className={colors[mitmdfStatus] || 'bg-destructive'}>{mitmdfStatus}</Badge>;
    };

    return (
        <Card>
            <CardHeader>
                <div className="flex flex-row gap-2 justify-between items-start">
                    <div>
                        <CardTitle>MITM Domain Fronting</CardTitle>
                        <CardDescription>
                            Bypass DPI using MITM decryption + domain fronting (patterniha method).
                            Set your browser/OS proxy to 127.0.0.1:{mitmdfSettings.socks5Port} and install the CA cert.
                        </CardDescription>
                    </div>
                    <Dialog>
                        <DialogTrigger asChild><Button variant="ghost" size="icon"><Settings className="size-4" /></Button></DialogTrigger>
                        <DialogContent>
                            <DialogHeader><DialogTitle>Reset Settings</DialogTitle><DialogDescription>Reset MITM-DF settings to defaults?</DialogDescription></DialogHeader>
                            <DialogFooter>
                                <DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose>
                                <DialogClose asChild><Button variant="destructive" onClick={resetMITMDFSettings}>Reset</Button></DialogClose>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                </div>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
                {/* Status + Actions */}
                <div className="flex items-center gap-3 flex-wrap">
                    {statusBadge()}
                    <Button onClick={handleStart} disabled={!isStopped || !assetsReady}>
                        {mitmdfStatus === 'starting'
                            ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Starting...</>
                            : <><Play className="mr-2 h-4 w-4" />Start</>
                        }
                    </Button>
                    <Dialog>
                        <DialogTrigger asChild>
                            <Button variant="destructive" disabled={mitmdfStatus !== 'running'}>
                                {mitmdfStatus === 'stopping'
                                    ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Stopping...</>
                                    : <><Square className="mr-2 h-4 w-4" />Stop</>
                                }
                            </Button>
                        </DialogTrigger>
                        <DialogContent>
                            <DialogHeader><DialogTitle>Stop MITM-DF</DialogTitle><DialogDescription>Stop the MITM domain fronting service?</DialogDescription></DialogHeader>
                            <DialogFooter>
                                <DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose>
                                <DialogClose asChild><Button variant="destructive" onClick={handleStop}>Stop</Button></DialogClose>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                </div>

                {/* Assets */}
                <div className="border rounded-md p-3 space-y-3">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            {checkingAssets ? <Loader2 className="size-4 animate-spin" /> : assetsReady ? <CheckCircle2 className="size-4 text-green-500" /> : <ShieldX className="size-4 text-destructive" />}
                            <p className="text-sm font-medium">Geo Assets (geosite.dat + geoip.dat)</p>
                        </div>
                        <Button variant="outline" size="sm" onClick={downloadAssets} disabled={downloadingAssets || !isStopped}>
                            {downloadingAssets ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
                            {assetsReady ? "Re-download" : "Download"}
                        </Button>
                    </div>
                    {!assetsReady && !checkingAssets && <p className="text-xs text-destructive">Required for geosite/geoip routing. Download to continue.</p>}
                </div>

                {/* Certificate */}
                <div className="border rounded-md p-3 space-y-3">
                    <div className="flex items-center gap-2">
                        {certChecked && (certExists ? <ShieldCheck className="size-4 text-green-500" /> : <ShieldX className="size-4 text-destructive" />)}
                        <p className="text-sm font-medium">Certificate</p>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <div className="flex flex-col gap-1.5"><Label className="text-xs">Cert Path</Label><Input value={mitmdfSettings.certPath} onChange={e => updateMITMDFSettings({ certPath: e.target.value })} disabled={!isStopped} /></div>
                        <div className="flex flex-col gap-1.5"><Label className="text-xs">Key Path</Label><Input value={mitmdfSettings.keyPath} onChange={e => updateMITMDFSettings({ keyPath: e.target.value })} disabled={!isStopped} /></div>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                        <Button variant="outline" size="sm" onClick={generateCert} disabled={generatingCert || !isStopped}>
                            {generatingCert ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                            {certExists ? "Regenerate" : "Generate Self-Signed Cert"}
                        </Button>
                        <Button variant="outline" size="sm" onClick={handleDownloadCert} disabled={!certExists}>
                            <Download className="mr-1.5 size-3.5" />Download
                        </Button>
                        <Button variant="outline" size="sm" onClick={handleInstallCert} disabled={installingCert || !certExists}>
                            {installingCert ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-1.5 size-3.5" />}
                            Install to System
                        </Button>
                    </div>
                    {installMsg && <p className="text-xs text-destructive whitespace-pre-wrap">{installMsg}</p>}
                    {certChecked && !certExists && <p className="text-xs text-destructive">Certificate not found. Generate one.</p>}
                </div>

                {/* Ports */}
                <div className="flex flex-col gap-1.5 max-w-xs">
                    <Label className="text-xs">SOCKS5/HTTP Proxy Port</Label>
                    <InputNumber min={1} max={65535} value={mitmdfSettings.socks5Port} onChange={v => updateMITMDFSettings({ socks5Port: v })} disabled={!isStopped} />
                </div>

                {/* Service Groups */}
                <div className="space-y-3">
                    <div className="flex items-center justify-between">
                        <p className="text-sm font-medium">Service Groups</p>
                        <Button variant="outline" size="sm" onClick={addGroup} disabled={!isStopped}>
                            <Plus className="mr-1.5 size-3.5" />Add Group
                        </Button>
                    </div>
                    {mitmdfSettings.groups.map((g, idx) => (
                        <div key={idx} className="border rounded-md p-3 space-y-2">
                            <div className="flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <Checkbox checked={g.enabled} onCheckedChange={(c) => updateGroup(idx, { enabled: Boolean(c) })} disabled={!isStopped} />
                                    <Input
                                        className="h-7 text-sm font-medium w-32"
                                        value={g.name}
                                        onChange={e => updateGroup(idx, { name: e.target.value })}
                                        disabled={!isStopped}
                                    />
                                </div>
                                <Button variant="ghost" size="icon" className="size-7 shrink-0" onClick={() => removeGroup(idx)} disabled={!isStopped || mitmdfSettings.groups.length <= 1} title="Remove group">
                                    <Trash2 className="size-3.5 text-destructive" />
                                </Button>
                            </div>
                            <AnimatePresence>
                                {g.enabled && (
                                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="space-y-2 overflow-hidden">
                                        <div className="flex flex-col gap-1.5">
                                            <Label className="text-xs">Front Domain (SNI)</Label>
                                            <Input value={g.frontDomain} onChange={e => updateGroup(idx, { frontDomain: e.target.value })} disabled={!isStopped} placeholder="www.example.com" />
                                        </div>
                                        <div className="flex flex-col gap-1.5">
                                            <Label className="text-xs">Extra Domains <span className="text-muted-foreground">(one per line, supports domain:/geosite:/geoip: prefixes)</span></Label>
                                            <Textarea className="h-20 font-mono text-sm" value={g.extraDomains.join('\n')} onChange={e => updateGroup(idx, { extraDomains: e.target.value.split('\n').map(s => s.trim()).filter(Boolean) })} disabled={!isStopped} placeholder="example.com&#10;geosite:google" />
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    ))}
                </div>

                {/* Extra IR domains */}
                <div className="flex flex-col gap-1.5">
                    <Label className="text-xs">Extra Iranian / Direct Domains <span className="text-muted-foreground">(one per line, bypass MITM)</span></Label>
                    <Textarea className="h-16 font-mono text-sm" value={extraIRText} onChange={e => setExtraIRText(e.target.value)} disabled={!isStopped} placeholder="domain:example.ir" />
                </div>

                {/* Auto Detect */}
                <div className="border rounded-md p-3 space-y-3">
                    <div className="flex items-center gap-2">
                        <Search className="size-4" />
                        <p className="text-sm font-medium">Auto Detect — Domain Fronting Probe</p>
                    </div>
                    <p className="text-xs text-muted-foreground">
                        Test whether a target domain can be fronted through each CDN. The tool connects to each front domain's server via TLS and sends an HTTP request with your target domain as the Host header. A successful response means domain fronting is possible.
                    </p>
                    <div className="flex gap-2">
                        <Input
                            className="flex-1 font-mono text-sm"
                            placeholder="target-domain.com"
                            value={probeTarget}
                            onChange={e => setProbeTarget(e.target.value)}
                            disabled={probing}
                        />
                        <Button onClick={handleProbe} disabled={probing || !probeTarget.trim()}>
                            {probing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
                            Detect
                        </Button>
                    </div>

                    <details className="text-xs text-muted-foreground">
                        <summary className="cursor-pointer">Front domains to probe ({probeDomainsText.split('\n').filter(Boolean).length})</summary>
                        <Textarea
                            className="mt-2 h-24 font-mono text-sm"
                            value={probeDomainsText}
                            onChange={e => setProbeDomainsText(e.target.value)}
                            disabled={probing}
                            placeholder="www.google.com&#10;www.microsoft.com"
                        />
                    </details>

                    {probeResults && (
                        <div className="space-y-1 max-h-64 overflow-y-auto">
                            {probeResults.map((r, i) => {
                                const matchedGroup = mitmdfSettings.groups.find(g => g.frontDomain === r.frontDomain && g.enabled);
                                const alreadyInGroup = matchedGroup && matchedGroup.extraDomains.includes(probeTarget.trim());
                                return (
                                    <div key={i} className="flex items-center justify-between gap-2 py-1.5 px-2 rounded hover:bg-muted/50 text-sm">
                                        <div className="flex items-center gap-2 min-w-0 flex-1">
                                            {r.success
                                                ? <CheckCircle2 className="size-3.5 shrink-0 text-green-500" />
                                                : <XCircle className="size-3.5 shrink-0 text-destructive" />
                                            }
                                            <span className="font-mono truncate">{r.frontDomain}</span>
                                            {r.success && (
                                                <span className="text-muted-foreground shrink-0">
                                                    HTTP {r.statusCode} · {r.latencyMs}ms
                                                </span>
                                            )}
                                            {r.error && (
                                                <span className="text-muted-foreground truncate" title={r.error}>{r.error}</span>
                                            )}
                                        </div>
                                        {r.success && matchedGroup && (
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                className="shrink-0 h-6 text-xs"
                                                onClick={() => addTargetToGroup(r.frontDomain)}
                                                disabled={alreadyInGroup}
                                            >
                                                {alreadyInGroup ? "Added" : `Add to ${matchedGroup.name}`}
                                            </Button>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
