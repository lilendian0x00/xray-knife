import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Checkbox } from "@/components/ui/checkbox";
import axios from 'axios';
import { Loader2, Globe, ClipboardCopy, Settings } from 'lucide-react';

export interface HttpResult {
    link: string;
    status: 'passed' | 'failed' | 'broken' | 'timeout' | 'semi-passed';
    reason: string;
    tls: string;
    ip: string;
    delay: number;
    download: number;
    upload: number;
    location: string;
}

interface HttpTesterTabProps {
    results: HttpResult[];
    setResults: React.Dispatch<React.SetStateAction<HttpResult[]>>;
}

export function HttpTesterTab({ results, setResults }: HttpTesterTabProps) {
    const [httpTestConfigs, setHttpTestConfigs] = useState('');
    const [threadCount, setThreadCount] = useState(50);
    const [maxDelay, setMaxDelay] = useState(5000);
    const [coreType, setCoreType] = useState('auto');
    const [destURL, setDestURL] = useState('https://cloudflare.com/cdn-cgi/trace');
    const [httpMethod, setHttpMethod] = useState('GET');
    const [insecureTLS, setInsecureTLS] = useState(false);
    const [speedtest, setSpeedtest] = useState(false);
    const [getIPInfo, setGetIPInfo] = useState(true);
    const [speedtestAmount, setSpeedtestAmount] = useState(10000);
    const [isTesting, setIsTesting] = useState(false);

    const sortedResults = useMemo(() => {
        return [...results].sort((a, b) => {
            if (a.status === 'passed' && b.status !== 'passed') return -1;
            if (a.status !== 'passed' && b.status === 'passed') return 1;
            return a.delay - b.delay;
        });
    }, [results]);

    const handleRunHttpTest = async () => {
        if (!httpTestConfigs.trim()) {
            toast.error("HTTP Test configurations cannot be empty.");
            return;
        }
        setResults([]); // Clear previous results
        setIsTesting(true);
        toast.info("Starting HTTP configuration test...");
        try {
            const links = httpTestConfigs.trim().split('\n').map(link => link.trim()).filter(link => link);
            await axios.post('/api/v1/http/test', {
                links,
                threadCount,
                maxDelay,
                coreType,
                destURL,
                httpMethod,
                insecureTLS,
                speedtest,
                getIPInfo,
                speedtestAmount,
            });
            toast.success("HTTP test initiated. See results below.");
        } catch (error) {
            console.error("Failed to start HTTP test:", error);
            toast.error("Failed to start HTTP test.");
        } finally {
            setIsTesting(false);
        }
    };

    const handleCopyLink = (link: string) => {
        navigator.clipboard.writeText(link).then(() => {
            toast.success("Link copied to clipboard!");
        }, (err) => {
            toast.error("Failed to copy link.");
            console.error('Could not copy text: ', err);
        });
    };

    const getStatusBadgeVariant = (status: HttpResult['status']): "default" | "secondary" | "destructive" => {
        switch (status) {
            case 'passed':
                return 'default'; // Green in shadcn default
            case 'semi-passed':
                return 'secondary'; // Yellow-ish/Gray
            default:
                return 'destructive'; // Red
        }
    };

    return (
        <div className="flex flex-col gap-4">
            <Card>
                <CardHeader>
                    <CardTitle>Configuration Tester</CardTitle>
                    <CardDescription>Test a list of configurations for latency and speed.</CardDescription>
                </CardHeader>
                <CardContent className="flex flex-col gap-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="thread-count">Thread Count</Label>
                            <Input
                                id="thread-count"
                                type="number"
                                min={1}
                                max={200}
                                value={threadCount}
                                onChange={(e) => setThreadCount(Math.max(1, parseInt(e.target.value) || 50))}
                            />
                        </div>
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="max-delay">Max Delay (ms)</Label>
                            <Input
                                id="max-delay"
                                type="number"
                                min={1000}
                                max={30000}
                                step={1000}
                                value={maxDelay}
                                onChange={(e) => setMaxDelay(Math.max(1000, parseInt(e.target.value) || 5000))}
                            />
                        </div>
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="core-type">Core Type</Label>
                            <Select value={coreType} onValueChange={setCoreType}>
                                <SelectTrigger id="core-type">
                                    <SelectValue placeholder="Select core type" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="auto">Auto</SelectItem>
                                    <SelectItem value="xray">Xray</SelectItem>
                                    <SelectItem value="singbox">Sing-box</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    <div className="flex flex-col gap-3">
                        <Label htmlFor="http-test-configs">Configuration Links</Label>
                        <Textarea
                            id="http-test-configs"
                            placeholder="Enter config links, one per line..."
                            className="h-40 font-mono text-sm resize-y min-h-[100px]"
                            value={httpTestConfigs}
                            onChange={(e) => setHttpTestConfigs(e.target.value)}
                        />
                    </div>
                    <div className="flex flex-col sm:flex-row gap-4">
                        <Button onClick={handleRunHttpTest} disabled={isTesting}>
                            {isTesting ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Testing...
                                </>
                            ) : (
                                <>
                                    <Globe className="mr-2 h-4 w-4" />
                                    Run Test
                                </>
                            )}
                        </Button>
                        <Dialog>
                            <DialogTrigger asChild>
                                <Button variant="outline">
                                    <Settings className="mr-2 h-4 w-4" />
                                    Advanced Settings
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[425px]">
                                <DialogHeader>
                                    <DialogTitle>Advanced Settings</DialogTitle>
                                    <DialogDescription>
                                        Modify advanced options for the HTTP tester.
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="grid gap-4 py-4">
                                    <div className="grid grid-cols-4 items-center gap-4">
                                        <Label htmlFor="dest-url" className="text-right">Test URL</Label>
                                        <Input id="dest-url" value={destURL} onChange={(e) => setDestURL(e.target.value)} className="col-span-3" />
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                        <Label htmlFor="http-method-modal" className="text-center">Method</Label>
                                        <Select value={httpMethod} onValueChange={setHttpMethod}>
                                            <SelectTrigger id="http-method-modal" className="col-span-3">
                                                <SelectValue placeholder="Select method" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="GET">GET</SelectItem>
                                                <SelectItem value="POST">POST</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
                                        <div className="flex items-center space-x-2">
                                            <Checkbox id="speedtest" checked={speedtest} onCheckedChange={(checked) => setSpeedtest(Boolean(checked))} />
                                            <Label htmlFor="speedtest" className="font-normal">Speed Test</Label>
                                        </div>
                                    </div>
                                    {speedtest && (
                                        <div className="grid grid-cols-4 items-center gap-4">
                                            <Label htmlFor="speedtest-amount" className="text-right">Speedtest Amount (KB)</Label>
                                            <Input
                                                className="col-span-3"
                                                id="speedtest-amount"
                                                type="number"
                                                min={100}
                                                value={speedtestAmount}
                                                onChange={(e) => setSpeedtestAmount(Number(e.target.value))}
                                            />
                                        </div>
                                    )}
                                    <div className="flex items-center justify-end space-x-2">
                                        <Checkbox id="get-ip-info-modal" checked={getIPInfo} onCheckedChange={(checked) => setGetIPInfo(Boolean(checked))} />
                                        <Label htmlFor="get-ip-info-modal" className="font-normal">Get IP Info</Label>
                                    </div>
                                    <div className="flex items-center justify-end space-x-2">
                                        <Checkbox id="insecure-tls-modal" checked={insecureTLS} onCheckedChange={(checked) => setInsecureTLS(Boolean(checked))} />
                                        <Label htmlFor="insecure-tls-modal" className="font-normal">Insecure TLS</Label>
                                    </div>
                                </div>
                            </DialogContent>
                        </Dialog>
                    </div>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Test Results</CardTitle>
                    <CardDescription>
                        Showing {results.length} results. Sorted by delay (fastest first).
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="border rounded-md">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead className="w-[100px]">Status</TableHead>
                                    <TableHead>Delay</TableHead>
                                    <TableHead>Download</TableHead>
                                    <TableHead>Upload</TableHead>
                                    <TableHead>Location</TableHead>
                                    <TableHead>Link</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {sortedResults.length > 0 ? (
                                    sortedResults.map((result, index) => (
                                        <TableRow key={index}>
                                            <TableCell>
                                                <Badge variant={getStatusBadgeVariant(result.status)} className="capitalize">
                                                    {result.status}
                                                </Badge>
                                            </TableCell>
                                            <TableCell>{result.status === 'passed' ? `${result.delay}ms` : '-'}</TableCell>
                                            <TableCell>{result.download > 0 ? `${result.download.toFixed(2)} Mbps` : '-'}</TableCell>
                                            <TableCell>{result.upload > 0 ? `${result.upload.toFixed(2)} Mbps` : '-'}</TableCell>
                                            <TableCell>{result.location !== 'null' ? result.location : 'N/A'}</TableCell>
                                            <TableCell className="font-mono text-xs">
                                                <div className="flex items-center justify-between gap-2 max-w-sm">
                                                    <span className="truncate">{result.link}</span>
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        className="h-7 w-7 shrink-0"
                                                        onClick={() => handleCopyLink(result.link)}
                                                    >
                                                        <ClipboardCopy className="h-4 w-4" />
                                                    </Button>
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={6} className="h-24 text-center">
                                            No results yet. Run a test to see the output here.
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