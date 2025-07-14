import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Checkbox } from "@/components/ui/checkbox";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import axios from 'axios';
import { Loader2, Play, StopCircle, Settings } from 'lucide-react';

// Matches the Go backend struct for WebSocket messages
export interface ScanResult {
    ip: string;
    latency_ms: number;
    download_mbps: number;
    upload_mbps: number;
    error: string; // The backend sends this as `error_str`
}

export type ScanStatus = 'idle' | 'scanning' | 'stopping';

interface CfScannerTabProps {
    results: ScanResult[];
    setResults: React.Dispatch<React.SetStateAction<ScanResult[]>>;
    status: ScanStatus;
    setStatus: React.Dispatch<React.SetStateAction<ScanStatus>>;
}

export function CfScannerTab({ results, setResults, status, setStatus }: CfScannerTabProps) {
    // Basic settings
    const [subnets, setSubnets] = useState('104.16.0.0/16\n104.24.0.0/16');
    const [threadCount, setThreadCount] = useState(100);
    const [timeout, setTimeout] = useState(5000);
    const [retry, setRetry] = useState(1);
    const [resume, setResume] = useState(false);

    // Speed test settings
    const [doSpeedtest, setDoSpeedtest] = useState(false);
    const [speedtestTop, setSpeedtestTop] = useState(10);
    const [speedtestConcurrency, setSpeedtestConcurrency] = useState(4);
    const [speedtestTimeout, setSpeedtestTimeout] = useState(30);
    const [downloadMB, setDownloadMB] = useState(10);
    const [uploadMB, setUploadMB] = useState(5);

    // Advanced/Proxy settings
    const [configLink, setConfigLink] = useState('');
    const [insecureTLS, setInsecureTLS] = useState(false);
    const [shuffleIPs, setShuffleIPs] = useState(false);
    const [shuffleSubnets, setShuffleSubnets] = useState(false);

    // Display settings
    const [onlySpeedtestResults, setOnlySpeedtestResults] = useState(false);

    const filteredAndSortedResults = useMemo(() => {
        // FIX: Filter out results with errors first. This addresses "must not show non working IPs".
        const successfulResults = results.filter(r => !r.error);

        const filtered = onlySpeedtestResults
            ? successfulResults.filter(r => r.download_mbps > 0 || r.upload_mbps > 0)
            : successfulResults;

        return [...filtered].sort((a, b) => {
            if (a.latency_ms !== b.latency_ms) return a.latency_ms - b.latency_ms;
            // Secondary sort: higher download speed is better
            if (b.download_mbps !== a.download_mbps) return b.download_mbps - a.download_mbps;
            // Tertiary sort: higher upload speed is better
            return b.upload_mbps - a.upload_mbps;
        });
    }, [results, onlySpeedtestResults]);

    const handleStartScan = async () => {
        if (!subnets.trim()) {
            toast.error("Subnets field cannot be empty.");
            return;
        }
        setResults([]);
        setStatus('scanning');
        toast.info("Starting CF scan...");
        try {
            await axios.post('/api/v1/scanner/cf/start', {
                Subnets: subnets.trim().split('\n').map(s => s.trim()).filter(s => s),
                ThreadCount: threadCount,
                RequestTimeout: timeout,
                RetryCount: retry,
                DoSpeedtest: doSpeedtest,
                SpeedtestTop: speedtestTop,
                SpeedtestConcurrency: speedtestConcurrency,
                SpeedtestTimeout: speedtestTimeout,
                DownloadMB: downloadMB,
                UploadMB: uploadMB,
                ConfigLink: configLink,
                InsecureTLS: insecureTLS,
                ShuffleIPs: shuffleIPs,
                ShuffleSubnets: shuffleSubnets,
                Resume: resume,
                Verbose: true, // Always let backend log everything
            });
            // The UI status will be updated to 'idle' via a WebSocket message from the backend when the scan finishes or errors.
        } catch (error) {
            console.error("Failed to start scan:", error);
            const errorMsg = axios.isAxiosError(error) ? error.response?.data?.error : "An unknown error occurred.";
            toast.error(`Failed to start scan: ${errorMsg}`);
            // FIX: If the start command fails, immediately reset the status to idle.
            setStatus('idle');
        }
    };

    const handleStopScan = async () => {
        setStatus('stopping');
        toast.info("Sending stop signal...");
        try {
            await axios.post('/api/v1/scanner/cf/stop');
            toast.success("Stop signal sent. The scan will halt shortly.");
            // The UI status will be updated to 'idle' via a WebSocket message from the backend once the stop is confirmed.
        } catch (error) {
            console.error("Failed to stop scan:", error);
            toast.error("Failed to send stop signal.");
            // FIX: If the stop command fails, revert the status to 'scanning' as it's likely still running.
            setStatus('scanning');
        }
    };

    return (
        <div className="flex flex-col gap-4">
            <Card>
                <CardHeader>
                    <CardTitle>Cloudflare Scanner</CardTitle>
                    <CardDescription>Find optimal Cloudflare IPs by scanning subnets for latency and speed.</CardDescription>
                </CardHeader>
                <CardContent className="flex flex-col gap-4">
                    <Textarea
                        id="subnets"
                        placeholder="Enter subnets (e.g., 104.16.0.0/16) or IP ranges, one per line..."
                        className="h-28 font-mono text-sm resize-y"
                        value={subnets}
                        onChange={(e) => setSubnets(e.target.value)}
                        disabled={status !== 'idle'}
                    />
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="threads">Threads</Label>
                            <Input id="threads" type="number" min={1} value={threadCount} onChange={(e) => setThreadCount(Number(e.target.value))} disabled={status !== 'idle'} />
                        </div>
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="timeout">Timeout (ms)</Label>
                            <Input id="timeout" type="number" min={100} value={timeout} onChange={(e) => setTimeout(Number(e.target.value))} disabled={status !== 'idle'} />
                        </div>
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="retry">Retries</Label>
                            <Input id="retry" type="number" min={0} value={retry} onChange={(e) => setRetry(Number(e.target.value))} disabled={status !== 'idle'} />
                        </div>
                         <div className="flex items-end pb-2 gap-2">
                            <Checkbox id="resume" checked={resume} onCheckedChange={(c) => setResume(Boolean(c))} disabled={status !== 'idle'} />
                            <Label htmlFor="resume">Resume Scan</Label>
                        </div>
                    </div>
                    <div className="flex items-center space-x-2">
                        <Checkbox id="speedtest" checked={doSpeedtest} onCheckedChange={(c) => setDoSpeedtest(Boolean(c))} disabled={status !== 'idle'} />
                        <Label htmlFor="speedtest">Perform Speed Test on Fastest IPs</Label>
                    </div>
                    {doSpeedtest && (
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 border p-4 rounded-md">
                            <div className="flex flex-col gap-2">
                                <Label htmlFor="speedtest-top">Test Top N IPs</Label>
                                <Input id="speedtest-top" type="number" min={1} value={speedtestTop} onChange={(e) => setSpeedtestTop(Number(e.target.value))} disabled={status !== 'idle'} />
                            </div>
                            <div className="flex flex-col gap-2">
                                <Label htmlFor="speedtest-concurrency">Concurrency</Label>
                                <Input id="speedtest-concurrency" type="number" min={1} value={speedtestConcurrency} onChange={(e) => setSpeedtestConcurrency(Number(e.target.value))} disabled={status !== 'idle'} />
                            </div>
                            <div className="flex flex-col gap-2">
                                <Label htmlFor="download-mb">Download (MB)</Label>
                                <Input id="download-mb" type="number" min={1} value={downloadMB} onChange={(e) => setDownloadMB(Number(e.target.value))} disabled={status !== 'idle'} />
                            </div>
                             <div className="flex flex-col gap-2">
                                <Label htmlFor="upload-mb">Upload (MB)</Label>
                                <Input id="upload-mb" type="number" min={1} value={uploadMB} onChange={(e) => setUploadMB(Number(e.target.value))} disabled={status !== 'idle'} />
                            </div>
                        </div>
                    )}
                     <div className="flex gap-4 flex-wrap">
                        <Button onClick={handleStartScan} disabled={status !== 'idle'}>
                            {status === 'scanning' ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Scanning...</> : <><Play className="mr-2 h-4 w-4" />Start Scan</>}
                        </Button>
                        <Button onClick={handleStopScan} variant="destructive" disabled={status !== 'scanning'}>
                            {status === 'stopping' ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Stopping...</> : <><StopCircle className="mr-2 h-4 w-4" />Stop Scan</>}
                        </Button>
                         <Dialog>
                            <DialogTrigger asChild>
                                <Button variant="outline" disabled={status !== 'idle'}>
                                    <Settings className="mr-2 h-4 w-4" />
                                    Advanced Settings
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[480px]">
                                <DialogHeader>
                                    <DialogTitle>Advanced Scan Settings</DialogTitle>
                                    <DialogDescription>
                                        Configure advanced options like proxies and randomization.
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="grid gap-4 py-4">
                                    <div className="flex items-center space-x-2">
                                        <Checkbox id="shuffle-ips" checked={shuffleIPs} onCheckedChange={(c) => setShuffleIPs(Boolean(c))} />
                                        <Label htmlFor="shuffle-ips">Shuffle IPs within a subnet</Label>
                                    </div>
                                     <div className="flex items-center space-x-2">
                                        <Checkbox id="shuffle-subnets" checked={shuffleSubnets} onCheckedChange={(c) => setShuffleSubnets(Boolean(c))} />
                                        <Label htmlFor="shuffle-subnets">Shuffle the order of subnets</Label>
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="config-link">Proxy Config Link (Optional)</Label>
                                        <Input id="config-link" placeholder="vless://..." value={configLink} onChange={(e) => setConfigLink(e.target.value)} />
                                        <div className="flex items-center space-x-2">
                                            <Checkbox id="insecure-tls-proxy" checked={insecureTLS} onCheckedChange={(c) => setInsecureTLS(Boolean(c))} />
                                            <Label htmlFor="insecure-tls-proxy">Allow insecure TLS for proxy</Label>
                                        </div>
                                    </div>
                                     {doSpeedtest && (
                                        <div className="space-y-2">
                                            <Label htmlFor="speedtest-timeout">Speed Test Timeout (s)</Label>
                                            <Input id="speedtest-timeout" type="number" value={speedtestTimeout} onChange={(e) => setSpeedtestTimeout(Number(e.target.value))} />
                                        </div>
                                     )}
                                </div>
                            </DialogContent>
                        </Dialog>
                    </div>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-col gap-1.5">
                           <CardTitle>Scan Results</CardTitle>
                            <CardDescription>Showing {filteredAndSortedResults.length} successful results. Sorted by latency.</CardDescription>
                        </div>
                         {doSpeedtest && (
                            <div className="flex items-center space-x-2">
                                <Checkbox id="only-speedtest" checked={onlySpeedtestResults} onCheckedChange={(c) => setOnlySpeedtestResults(Boolean(c))} />
                                <Label htmlFor="only-speedtest">Show only speed-tested IPs</Label>
                            </div>
                        )}
                    </div>
                </CardHeader>
                <CardContent>
                    <div className="border rounded-md max-h-[500px] overflow-y-auto">
                        <Table>
                            <TableHeader className="sticky top-0 bg-muted/95 backdrop-blur-sm z-10">
                                <TableRow>
                                    <TableHead className="w-[150px]">IP</TableHead>
                                    <TableHead>Latency</TableHead>
                                    <TableHead>Download</TableHead>
                                    <TableHead>Upload</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {filteredAndSortedResults.length > 0 ? (
                                    filteredAndSortedResults.map((result) => (
                                        <TableRow key={result.ip}>
                                            <TableCell className="font-mono">{result.ip}</TableCell>
                                            <TableCell>
                                                <Badge variant="secondary">{`${result.latency_ms}ms`}</Badge>
                                            </TableCell>
                                            <TableCell>
                                                {result.download_mbps > 0 ? `${result.download_mbps.toFixed(2)} Mbps` : '-'}
                                            </TableCell>
                                            <TableCell>
                                                {result.upload_mbps > 0 ? `${result.upload_mbps.toFixed(2)} Mbps` : '-'}
                                            </TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={4} className="h-24 text-center">
                                            {status === 'scanning' ? "Scanning... successful results will appear here." : "No results yet. Start a scan to see the output."}
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}