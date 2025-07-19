import { useState, useMemo, useEffect } from "react";
import { useAutoAnimate } from '@formkit/auto-animate/react';
import { motion, AnimatePresence } from 'framer-motion';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { InputNumber } from "@/components/ui/input-number";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Loader2, Play, StopCircle, Settings, Search as SearchIcon, CloudDownload, Trash2, RefreshCcw, RotateCcw } from 'lucide-react';
import useDebounce from "react-use/lib/useDebounce";
import { useAppStore } from "@/stores/appStore";
import { api } from "@/services/api";
import { Progress } from "@/components/ui/progress";
import { usePersistentState } from "@/hooks/usePersistentState";

export function CfScannerTab() {
    const { cfScannerSettings, updateCfScannerSettings, resetCfScannerSettings, scanResults, clearScanResults, scanStatus, setScanStatus, scanProgress } = useAppStore();

    const [subnets, setSubnets] = usePersistentState('cfscanner-subnets-input', '');
    const [isLoadingRanges, setIsLoadingRanges] = useState(false);
    const [searchTerm, setSearchTerm] = useState("");
    const [debouncedSearchTerm, setDebouncedSearchTerm] = useState("");
    const [onlySpeedtestResults, setOnlySpeedtestResults] = useState(false);

    useDebounce(() => setDebouncedSearchTerm(searchTerm), 300, [searchTerm]);
    const [animationParent] = useAutoAnimate<HTMLTableSectionElement>();

    const isBusy = scanStatus === 'running' || scanStatus === 'stopping' || scanStatus === 'starting';
    const progressValue = scanProgress.total > 0 ? (scanProgress.completed / scanProgress.total) * 100 : 0;

    useEffect(() => {
        if (scanStatus === 'idle') {
            setSearchTerm("");
        }
    }, [scanStatus]);

    const filteredAndSortedResults = useMemo(() => {
        const successfulResults = scanResults.filter(r => !r.error);
        const speedtestFiltered = onlySpeedtestResults ? successfulResults.filter(r => r.download_mbps > 0 || r.upload_mbps > 0) : successfulResults;
        const searchFiltered = debouncedSearchTerm ? speedtestFiltered.filter(r => r.ip.includes(debouncedSearchTerm.trim())) : speedtestFiltered;
        return [...searchFiltered].sort((a, b) => a.latency_ms - b.latency_ms);
    }, [scanResults, onlySpeedtestResults, debouncedSearchTerm]);

    const handleLoadRanges = async () => {
        setIsLoadingRanges(true);
        toast.info("Fetching Cloudflare IP ranges...");
        try {
            const response = await api.getCfScannerRanges();
            if (response.data?.ranges) setSubnets(response.data.ranges.join('\n'));
            toast.success("Successfully loaded Cloudflare IP ranges.");
        } catch (error) { toast.error("Failed to load ranges."); } finally {
            setIsLoadingRanges(false);
        }
    };

    const handleStartScan = async (isResuming: boolean) => {
        if (!subnets.trim()) { toast.error("Subnets field cannot be empty."); return; }
        setScanStatus('starting');
        setSearchTerm("");
        const toastId = toast.loading(isResuming ? "Resuming scan..." : "Starting new scan...");

        if (!isResuming) {
            try { await api.clearCfScanHistory(); clearScanResults(); } catch { toast.warning("Could not clear previous history, continuing."); }
        }

        try {
            await api.startCfScan(cfScannerSettings, subnets.trim().split('\n').filter(s => s), isResuming);
            toast.success("Scan initiated.", { id: toastId });
        } catch (err: any) {
            const errorMsg = err.response?.data?.error || "An unknown error occurred.";
            toast.error(`Failed to start scan: ${errorMsg}`, { id: toastId });
            setScanStatus('idle');
        }
    };

    const handleStopScan = async () => {
        setScanStatus('stopping');
        const toastId = toast.loading("Sending stop signal...");
        try {
            await api.stopCfScan();
            toast.success("Scanner has been stopped.", { id: toastId });
            setScanStatus('idle');
        } catch {
            toast.error("Failed to send stop signal.", { id: toastId });
            setScanStatus('running'); // Revert to running on API failure
        }
    };

    const handleClearHistory = async () => {
        try {
            await api.clearCfScanHistory();
            clearScanResults();
            toast.success("Scanner history has been cleared.");
        } catch (error) {
            toast.error("Failed to clear scanner history.");
        }
    }

    return (
        <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-5 lg:gap-8">
            <div className="grid auto-rows-max items-start gap-4 lg:col-span-2">
                <Card>
                    <CardHeader>
                        <div className="flex flex-row gap-2 justify-between items-start">
                            <div className="flex flex-col"><CardTitle>Cloudflare Scanner</CardTitle><CardDescription>Find optimal IPs by scanning subnets.</CardDescription></div>
                            <Dialog><DialogTrigger asChild><Button variant="ghost" size="icon" className="shrink-0"><RotateCcw className="size-4" /></Button></DialogTrigger>
                                <DialogContent><DialogHeader><DialogTitle>Reset Settings</DialogTitle><DialogDescription>Reset all scanner settings to defaults?</DialogDescription></DialogHeader>
                                    <DialogFooter><DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose><DialogClose asChild><Button variant="destructive" onClick={resetCfScannerSettings}>Reset</Button></DialogClose></DialogFooter>
                                </DialogContent>
                            </Dialog>
                        </div>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        <fieldset disabled={isBusy} className="space-y-4">
                            <div>
                                <div className="flex items-center justify-between mb-1"><Label htmlFor="subnets" className="text-xs text-muted-foreground">Subnets / IP Ranges</Label><Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={handleLoadRanges} disabled={isLoadingRanges}>{isLoadingRanges ? <Loader2 className="mr-1.5 size-3 animate-spin" /> : <CloudDownload className="mr-1.5 size-3" />} Load CF Ranges</Button></div>
                                <Textarea id="subnets" placeholder="Paste IP ranges here, one per line." className="font-mono" value={subnets} onChange={(e) => setSubnets(e.target.value)} />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="flex flex-col gap-2"><Label>Threads</Label><InputNumber min={1} max={1000} value={cfScannerSettings.threadCount} onChange={(v) => updateCfScannerSettings({ threadCount: v })} /></div>
                                <div className="flex flex-col gap-2"><Label>Timeout (ms)</Label><InputNumber min={100} step={100} value={cfScannerSettings.timeout} onChange={(v) => updateCfScannerSettings({ timeout: v })} /></div>
                                <div className="flex flex-col gap-2"><Label>Retries</Label><InputNumber min={0} max={10} value={cfScannerSettings.retry} onChange={(v) => updateCfScannerSettings({ retry: v })} /></div>
                            </div>
                            <div><Label className="flex items-center gap-2 cursor-pointer"><Checkbox checked={cfScannerSettings.doSpeedtest} onCheckedChange={(c) => updateCfScannerSettings({ doSpeedtest: Boolean(c) })} />Perform Speed Test</Label></div>
                            <AnimatePresence>{cfScannerSettings.doSpeedtest && (<motion.div key="st" initial={{ opacity: 0, maxHeight: 0, marginTop: 0, borderTopWidth: 0 }} animate={{ opacity: 1, maxHeight: "500px", marginTop: "1rem", borderTopWidth: "1px" }} exit={{ opacity: 0, maxHeight: 0, marginTop: 0, borderTopWidth: 0 }} className="border-t pt-4">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    <div className="flex flex-col gap-2"><Label>Test Top</Label><InputNumber min={1} value={cfScannerSettings.speedtestOptions.top} onChange={(v) => updateCfScannerSettings({ speedtestOptions: { ...cfScannerSettings.speedtestOptions, top: v } })} /></div>
                                    <div className="flex flex-col gap-2"><Label>Concurrency</Label><InputNumber min={1} value={cfScannerSettings.speedtestOptions.concurrency} onChange={(v) => updateCfScannerSettings({ speedtestOptions: { ...cfScannerSettings.speedtestOptions, concurrency: v } })} /></div>
                                    <div className="flex flex-col gap-2"><Label>DL (MB)</Label><InputNumber min={1} value={cfScannerSettings.speedtestOptions.downloadMB} onChange={(v) => updateCfScannerSettings({ speedtestOptions: { ...cfScannerSettings.speedtestOptions, downloadMB: v } })} /></div>
                                    <div className="flex flex-col gap-2"><Label>UL (MB)</Label><InputNumber min={1} value={cfScannerSettings.speedtestOptions.uploadMB} onChange={(v) => updateCfScannerSettings({ speedtestOptions: { ...cfScannerSettings.speedtestOptions, uploadMB: v } })} /></div>
                                </div>
                            </motion.div>)}</AnimatePresence>
                        </fieldset>
                        <div className="flex flex-col gap-4">
                            <div className="grid grid-cols-2 gap-4"><Button onClick={() => handleStartScan(false)} disabled={isBusy} size="lg">{scanStatus === 'starting' ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Starting...</> : scanStatus === 'running' ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Scanning...</> : <><Play className="mr-2 h-4 w-4" />New Scan</>}</Button><Button variant="secondary" onClick={() => handleStartScan(true)} disabled={isBusy || scanResults.length === 0} size="lg"><RefreshCcw className="mr-2 h-4 w-4" />Resume</Button></div>
                            <Button onClick={handleStopScan} variant="destructive" size={"lg"} disabled={scanStatus !== 'running'}>{scanStatus === 'stopping' ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Stopping...</> : <><StopCircle className="mr-2 h-4 w-4" />Stop Scan</>}</Button>
                            <AnimatePresence>
                                {scanStatus === 'running' && (
                                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-2 pt-2">
                                        <div className="flex justify-between text-sm text-muted-foreground"><span>Scanning IPs...</span><span>{scanProgress.completed} / {scanProgress.total}</span></div>
                                        <Progress value={progressValue} />
                                    </motion.div>
                                )}
                            </AnimatePresence>
                            <Dialog><DialogTrigger asChild><Button variant="outline" disabled={isBusy}><Settings className="mr-2 h-4 w-4" /> Advanced</Button></DialogTrigger>
                                <DialogContent className="sm:max-w-[480px]"><DialogHeader><DialogTitle>Advanced Scan Settings</DialogTitle><DialogDescription>Configure randomization and proxy options.</DialogDescription></DialogHeader>
                                    <fieldset disabled={isBusy} className="grid gap-6 py-4">
                                        <div className="space-y-3"><Label>Randomization</Label>
                                            <div className="flex flex-col gap-2 pl-2">
                                                <Label className="flex items-center gap-2 font-normal cursor-pointer"><Checkbox checked={cfScannerSettings.advancedOptions.shuffleIPs} onCheckedChange={(c) => updateCfScannerSettings({ advancedOptions: { ...cfScannerSettings.advancedOptions, shuffleIPs: Boolean(c) } })} />Shuffle IPs within a subnet</Label>
                                                <Label className="flex items-center gap-2 font-normal cursor-pointer"><Checkbox checked={cfScannerSettings.advancedOptions.shuffleSubnets} onCheckedChange={(c) => updateCfScannerSettings({ advancedOptions: { ...cfScannerSettings.advancedOptions, shuffleSubnets: Boolean(c) } })} />Shuffle the order of subnets</Label>
                                            </div>
                                        </div>
                                        <div className="space-y-2"><Label>Proxy Config (Optional)</Label><Input placeholder="vless://..." value={cfScannerSettings.advancedOptions.configLink} onChange={(e) => updateCfScannerSettings({ advancedOptions: { ...cfScannerSettings.advancedOptions, configLink: e.target.value } })} /><Label className="flex items-center gap-2 font-normal cursor-pointer"><Checkbox checked={cfScannerSettings.advancedOptions.insecureTLS} onCheckedChange={(c) => updateCfScannerSettings({ advancedOptions: { ...cfScannerSettings.advancedOptions, insecureTLS: Boolean(c) } })} />Allow Insecure TLS for proxy</Label></div>
                                        {cfScannerSettings.doSpeedtest && (<div className="space-y-2"><Label>Speed Test Timeout (s)</Label><InputNumber min={5} value={cfScannerSettings.speedtestOptions.timeout} onChange={(v) => updateCfScannerSettings({ speedtestOptions: { ...cfScannerSettings.speedtestOptions, timeout: v } })} /></div>)}
                                    </fieldset>
                                </DialogContent>
                            </Dialog>
                        </div>
                    </CardContent>
                </Card>
            </div>
            <div className="lg:col-span-3">
                <Card>
                    <CardHeader>
                        <div className="flex flex-wrap items-center justify-between gap-4">
                            <div className="flex flex-col gap-1.5"><CardTitle>Scan Results</CardTitle><CardDescription>Showing {filteredAndSortedResults.length} of {scanResults.length} results.</CardDescription></div>
                            <div className="relative w-full sm:w-64"><SearchIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" /><Input type="search" placeholder="Search by IP..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="pl-8" /></div>
                        </div>
                        <div className="flex items-center justify-between pt-4">
                            {cfScannerSettings.doSpeedtest && (<Label className="flex items-center gap-2 cursor-pointer"><Checkbox checked={onlySpeedtestResults} onCheckedChange={(c) => setOnlySpeedtestResults(Boolean(c))} />Show only speed-tested IPs</Label>)}
                            <Dialog><DialogTrigger asChild><Button variant="outline" size="sm" disabled={isBusy || scanResults.length === 0}><Trash2 className="mr-2 h-4 w-4" />Clear</Button></DialogTrigger>
                                <DialogContent>
                                    <DialogHeader><DialogTitle>Clear History</DialogTitle><DialogDescription>This will permanently delete all saved scanner results. Are you sure?</DialogDescription></DialogHeader>
                                    <DialogFooter><DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose><DialogClose asChild><Button variant="destructive" onClick={handleClearHistory}>Clear</Button></DialogClose></DialogFooter>
                                </DialogContent>
                            </Dialog>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div className="border rounded-md max-h-[600px] overflow-auto">
                            <Table><TableHeader className="sticky top-0 z-10 bg-muted/95 backdrop-blur-sm"><TableRow><TableHead className="w-[150px]">IP</TableHead><TableHead>Latency</TableHead><TableHead>Download</TableHead><TableHead>Upload</TableHead></TableRow></TableHeader>
                                <TableBody ref={animationParent}>
                                    {filteredAndSortedResults.length > 0 ? (filteredAndSortedResults.map((result) => (<TableRow key={result.ip}><TableCell className="font-mono">{result.ip}</TableCell><TableCell><Badge variant="secondary">{`${result.latency_ms}ms`}</Badge></TableCell><TableCell>{result.download_mbps > 0 ? `${result.download_mbps.toFixed(2)} Mbps` : '-'}</TableCell><TableCell>{result.upload_mbps > 0 ? `${result.upload_mbps.toFixed(2)} Mbps` : '-'}</TableCell></TableRow>))) : (<TableRow><TableCell colSpan={4} className="h-24 text-center text-muted-foreground">{isBusy ? "Scanning..." : (searchTerm ? "No results match your search." : "No results yet.")}</TableCell></TableRow>)}
                                </TableBody>
                            </Table>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}