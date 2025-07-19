import { useState, useMemo } from "react";
import { motion, AnimatePresence } from 'framer-motion';
import { useAutoAnimate } from '@formkit/auto-animate/react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { InputNumber } from "@/components/ui/input-number";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, DialogClose } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Checkbox } from "@/components/ui/checkbox";
import { Loader2, Globe, ClipboardCopy, Settings, RotateCcw, StopCircle, Trash2 } from 'lucide-react';
import { useAppStore } from "@/stores/appStore";
import { api } from "@/services/api";
import { type HttpResult } from "@/types/dashboard";
import { Progress } from "@/components/ui/progress";
import { usePersistentState } from "@/hooks/usePersistentState";

export function HttpTesterTab() {
    const { httpSettings, updateHttpSettings, resetHttpSettings, httpResults, clearHttpResults, httpTestStatus, setHttpTestStatus, httpTestProgress } = useAppStore();
    const [httpTestConfigs, setHttpTestConfigs] = usePersistentState('httptest-configs-input', '');

    const sortedResults = useMemo(() => {
        return [...httpResults].sort((a, b) => {
            if (a.status === 'passed' && b.status !== 'passed') return -1;
            if (a.status !== 'passed' && b.status === 'passed') return 1;
            return a.delay - b.delay;
        });
    }, [httpResults]);

    const isBusy = httpTestStatus === 'running' || httpTestStatus === 'stopping' || httpTestStatus === 'starting';
    const progressValue = httpTestProgress.total > 0 ? (httpTestProgress.completed / httpTestProgress.total) * 100 : 0;

    const [animationParent] = useAutoAnimate<HTMLTableSectionElement>();

    const handleRunHttpTest = async () => {
        if (!httpTestConfigs.trim()) { toast.error("HTTP Test configurations cannot be empty."); return; }
        clearHttpResults();
        setHttpTestStatus('starting');
        toast.info("Starting HTTP configuration test...");
        try {
            const links = httpTestConfigs.trim().split('\n').map(link => link.trim()).filter(link => link);
            await api.startHttpTest(httpSettings, links);
            toast.success("HTTP test initiated. See results below and in the live logs.");
        } catch (error: any) {
            const errorMessage = error.response?.data?.error || "An unknown error occurred.";
            toast.error(`Failed to start HTTP test: ${errorMessage}`);
            setHttpTestStatus('idle');
        }
    };

    const handleStopHttpTest = async () => {
        setHttpTestStatus('stopping');
        try {
            await api.stopHttpTest();
        } catch (error) {
            toast.error("Failed to stop the test.");
            setHttpTestStatus('running');
        }
    };

    const handleClearHistory = async () => {
        try {
            await api.clearHttpTestHistory();
            clearHttpResults();
            toast.success("HTTP test history cleared.");
        } catch (error) {
            toast.error("Failed to clear history.");
        }
    };

    const handleCopyLink = (link: string) => {
        navigator.clipboard.writeText(link).then(() => toast.success("Link copied!"), () => toast.error("Failed to copy link."));
    };

    const getStatusBadgeVariant = (status: HttpResult['status']): "default" | "secondary" | "destructive" => {
        if (status === 'passed') return 'default';
        if (status === 'semi-passed') return 'secondary';
        return 'destructive';
    };

    const getButtonContent = () => {
        switch (httpTestStatus) {
            case 'starting': return <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Starting...</>;
            case 'running': return <><Loader2 className="mr-2 h-4 w-4 animate-spin" />In Progress...</>;
            case 'stopping': return <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Stopping...</>;
            default: return <><Globe className="mr-2 h-4 w-4" />Run Test</>;
        }
    };

    return (
        <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-5 lg:gap-8">
            <div className="grid auto-rows-max items-start gap-4 lg:col-span-2">
                <Card>
                    <CardHeader>
                        <div className="flex flex-row gap-2 justify-between items-start">
                            <div className="flex flex-col"><CardTitle>Configuration Tester</CardTitle><CardDescription>Test a list of configurations for latency and speed.</CardDescription></div>
                            <Dialog><DialogTrigger asChild><Button variant="ghost" size="icon" className="shrink-0"><RotateCcw className="size-4" /></Button></DialogTrigger>
                                <DialogContent><DialogHeader><DialogTitle>Reset Settings</DialogTitle><DialogDescription>Reset all HTTP Tester settings to defaults?</DialogDescription></DialogHeader>
                                    <DialogFooter><DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose><DialogClose asChild><Button variant="destructive" onClick={resetHttpSettings}>Reset</Button></DialogClose></DialogFooter>
                                </DialogContent>
                            </Dialog>
                        </div>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-6">
                        <fieldset disabled={isBusy} className="space-y-6">
                            <div>
                                <Label htmlFor="http-test-configs" className="mb-2 block">Configuration Links</Label>
                                <Textarea id="http-test-configs" placeholder="Enter config links, one per line..." className="h-40 font-mono text-sm resize-y min-h-[100px]" value={httpTestConfigs} onChange={(e) => setHttpTestConfigs(e.target.value)} />
                            </div>
                            <div className="space-y-4">
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                    <div className="flex flex-col gap-2"><Label htmlFor="thread-count">Threads</Label><InputNumber id="thread-count" min={1} max={200} value={httpSettings.threadCount} onChange={(v) => updateHttpSettings({ threadCount: v })} /></div>
                                    <div className="flex flex-col gap-2"><Label htmlFor="max-delay">Max Delay (ms)</Label><InputNumber id="max-delay" min={1000} max={30000} step={1000} value={httpSettings.maxDelay} onChange={(v) => updateHttpSettings({ maxDelay: v })} /></div>
                                    <div className="flex flex-col gap-2"><Label htmlFor="core-type">Core</Label><Select value={httpSettings.coreType} onValueChange={(v) => updateHttpSettings({ coreType: v as any })}><SelectTrigger id="core-type"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="auto">Auto</SelectItem><SelectItem value="xray">Xray</SelectItem><SelectItem value="singbox">Sing-box</SelectItem></SelectContent></Select></div>
                                </div>
                                <div className="flex items-center space-x-2 pt-2"><Checkbox id="speedtest" checked={httpSettings.speedtest} onCheckedChange={(c) => updateHttpSettings({ speedtest: Boolean(c) })} /><Label htmlFor="speedtest" className="font-normal cursor-pointer">Enable Speed Test</Label></div>
                                <AnimatePresence>
                                    {httpSettings.speedtest && (
                                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden pl-6">
                                            <div className="flex flex-col gap-2"><Label htmlFor="speedtest-amount">Speed Test (KB)</Label><InputNumber id="speedtest-amount" min={100} step={1000} value={httpSettings.speedtestAmount} onChange={(v) => updateHttpSettings({ speedtestAmount: v })} className="max-w-xs" /></div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        </fieldset>
                        <div className="flex flex-col gap-2">
                            <div className="flex flex-col sm:flex-row gap-4">
                                <Button onClick={handleRunHttpTest} disabled={isBusy} className="flex-1">{getButtonContent()}</Button>
                                <Button onClick={handleStopHttpTest} variant="destructive" disabled={httpTestStatus !== 'running'} className="flex-1">
                                    <StopCircle className="mr-2 h-4 w-4" />Stop Test
                                </Button>
                                <Dialog>
                                    <DialogTrigger asChild><Button variant="outline" disabled={isBusy}><Settings className="mr-2 h-4 w-4" />Advanced</Button></DialogTrigger>
                                    <DialogContent className="sm:max-w-[425px]">
                                        <DialogHeader><DialogTitle>Advanced Settings</DialogTitle><DialogDescription>Modify advanced options for the HTTP tester.</DialogDescription></DialogHeader>
                                        <div className="flex flex-col gap-4 py-4">
                                            <div className="grid grid-cols-4 items-center gap-4"><Label htmlFor="dest-url" className="text-right">Test URL</Label><Input id="dest-url" value={httpSettings.destURL} onChange={(e) => updateHttpSettings({ destURL: e.target.value })} className="col-span-3" /></div>
                                            <div className="grid grid-cols-4 items-center gap-4"><Label htmlFor="http-method-modal" className="text-right">Method</Label><Select value={httpSettings.httpMethod} onValueChange={(v) => updateHttpSettings({ httpMethod: v as any })}><SelectTrigger id="http-method-modal" className="col-span-3"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="GET">GET</SelectItem><SelectItem value="POST">POST</SelectItem></SelectContent></Select></div>
                                            <div className="col-span-4 flex items-center justify-end space-x-2"><Checkbox id="get-ip-info-modal" checked={httpSettings.doIPInfo} onCheckedChange={(c) => updateHttpSettings({ doIPInfo: Boolean(c) })} /><Label htmlFor="get-ip-info-modal" className="font-normal cursor-pointer">Get IP Info</Label></div>
                                            <div className="col-span-4 flex items-center justify-end space-x-2"><Checkbox id="insecure-tls-modal" checked={httpSettings.insecureTLS} onCheckedChange={(c) => updateHttpSettings({ insecureTLS: Boolean(c) })} /><Label htmlFor="insecure-tls-modal" className="font-normal cursor-pointer">Allow Insecure TLS</Label></div>
                                        </div>
                                    </DialogContent>
                                </Dialog>
                            </div>
                            <AnimatePresence>
                                {httpTestStatus === 'running' && (
                                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-2 pt-4">
                                        <div className="flex justify-between text-sm text-muted-foreground">
                                            <span>Progress</span>
                                            <span>{httpTestProgress.completed} / {httpTestProgress.total}</span>
                                        </div>
                                        <Progress value={progressValue} />
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    </CardContent>
                </Card>
            </div>
            <div className="lg:col-span-3">
                <Card>
                    <CardHeader>
                        <div className="flex flex-wrap items-center justify-between gap-4">
                            <div className="flex flex-col gap-1.5"><CardTitle>Test Results</CardTitle><CardDescription>Showing {httpResults.length} results. Sorted by delay.</CardDescription></div>
                            <Dialog>
                                <DialogTrigger asChild><Button variant="outline" size="sm" disabled={isBusy || httpResults.length === 0}><Trash2 className="mr-2 h-4 w-4" />Clear History</Button></DialogTrigger>
                                <DialogContent>
                                    <DialogHeader><DialogTitle>Clear History</DialogTitle><DialogDescription>This will permanently delete all saved HTTP test results. Are you sure?</DialogDescription></DialogHeader>
                                    <DialogFooter><DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose><DialogClose asChild><Button variant="destructive" onClick={handleClearHistory}>Clear</Button></DialogClose></DialogFooter>
                                </DialogContent>
                            </Dialog>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div className="border rounded-md max-h-[600px] lg:min-h-[374px] overflow-auto">
                            <Table className="table-fixed">
                                <TableHeader className="sticky top-0 bg-muted/95 backdrop-blur-sm z-10">
                                    <TableRow>
                                        <TableHead className="w-[100px]">Status</TableHead>
                                        <TableHead>Delay</TableHead>
                                        <TableHead>Download</TableHead>
                                        <TableHead>Upload</TableHead>
                                        <TableHead>Location</TableHead>
                                        <TableHead>Link</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody ref={animationParent}>
                                    {sortedResults.length > 0 ? (
                                        sortedResults.map((result) => (
                                            <TableRow key={result.link}>
                                                <TableCell><Badge variant={getStatusBadgeVariant(result.status)} className="capitalize">{result.status}</Badge></TableCell>
                                                <TableCell>{result.status === 'passed' ? `${result.delay}ms` : '-'}</TableCell>
                                                <TableCell>{result.download > 0 ? `${result.download.toFixed(2)} Mbps` : '-'}</TableCell>
                                                <TableCell>{result.upload > 0 ? `${result.upload.toFixed(2)} Mbps` : '-'}</TableCell>
                                                <TableCell>{result.location !== 'null' ? result.location : 'N/A'}</TableCell>
                                                <TableCell className="font-mono text-xs">
                                                    <div className="flex items-center justify-between gap-2 max-w-sm">
                                                        <span className="truncate">{result.link}</span>
                                                        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={() => handleCopyLink(result.link)}>
                                                            <ClipboardCopy className="h-4 w-4" />
                                                        </Button>
                                                    </div>
                                                </TableCell>
                                            </TableRow>
                                        ))
                                    ) : (
                                        <TableRow>
                                            <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                                                {isBusy ? "Testing..." : "No results yet. Run a test to see results."}
                                            </TableCell>
                                        </TableRow>
                                    )}
                                </TableBody>
                            </Table>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}