import { useState, useEffect, useRef, useCallback } from "react";
import { Toaster } from "@/components/ui/sonner";
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Server, Globe, Search, TerminalSquare } from 'lucide-react';

import { ProxyTab } from "./dashboard/ProxyTab";
import { HttpTesterTab, type HttpResult } from "./dashboard/HttpTesterTab";
import { CfScannerTab, type ScanResult, type ScanStatus } from "./dashboard/CFScannerTab";

export type ProxyStatus = 'stopped' | 'running' | 'starting' | 'stopping';


export default function Dashboard() {
    const [proxyStatus, setProxyStatus] = useState<ProxyStatus>('stopped');
    const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
    const [httpResults, setHttpResults] = useState<HttpResult[]>([]);
    const [scanResults, setScanResults] = useState<ScanResult[]>([]);

    const terminalRef = useRef<HTMLDivElement>(null);
    const term = useRef<Terminal | null>(null);
    const fitAddon = useRef<FitAddon | null>(null);
    const ws = useRef<WebSocket | null>(null);

    const connectWebSocket = useCallback(() => {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        ws.current = new WebSocket(wsUrl);

        ws.current.onopen = () => term.current?.writeln("\x1b[32m[WebSocket] Connection established.\x1b[0m");

        ws.current.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                switch (message.type) {
                    case 'http_result':
                        setHttpResults(prev => [...prev, message.data]);
                        break;
                    case 'cfscan_result':
                        setScanResults(prev => {
                            const newResults = prev.filter(r => r.ip !== message.data.ip);
                            newResults.push(message.data);
                            return newResults;
                        });
                        break;
                    case 'cfscan_status':
                        // FIX: Ensure UI state is reset on both 'finished' and 'error'
                        if (message.data === 'finished') {
                            setScanStatus('idle');
                            toast.success("Cloudflare scan finished.");
                        } else if (message.data === 'error') {
                            setScanStatus('idle');
                            toast.error(`Scan failed: ${message.message}`);
                        }
                        break;
                    default:
                        // For generic log messages
                        term.current?.write(event.data);
                }
            } catch (e) {
                // If it's not valid JSON, treat it as a raw log line.
                term.current?.write(event.data);
            }
        };

        ws.current.onclose = () => {
            term.current?.writeln("\x1b[31m[WebSocket] Connection closed. Retrying in 3 seconds...\x1b[0m");
            setTimeout(connectWebSocket, 3000);
        };

        ws.current.onerror = (error) => {
            console.error("WebSocket error:", error);
            term.current?.writeln(`\x1b[31m[WebSocket] Error: ${error}\x1b[0m`);
            ws.current?.close();
        };
    }, []);

    useEffect(() => {
        if (terminalRef.current && !term.current) {
            const terminal = new Terminal({
                convertEol: true, cursorBlink: true, fontFamily: 'monospace',
                theme: { background: '#1c1917', foreground: '#f8fafc' }
            });
            const addon = new FitAddon();
            fitAddon.current = addon;
            terminal.loadAddon(addon);
            terminal.open(terminalRef.current);
            addon.fit();
            term.current = terminal;

            const resizeHandler = () => fitAddon.current?.fit();
            window.addEventListener('resize', resizeHandler);

            connectWebSocket();

            return () => {
                window.removeEventListener('resize', resizeHandler);
                term.current?.dispose();
                ws.current?.close();
            };
        }
    }, [connectWebSocket]);

    const getProxyStatusColor = (status: ProxyStatus) => {
        switch (status) {
            case 'running': return 'bg-green-500 text-white';
            case 'stopped': return 'bg-red-500 text-white';
            default: return 'bg-yellow-500 text-white';
        }
    };
    
    const clearLogs = () => term.current?.clear();

    return (
        <div className="bg-background text-foreground">
            <Toaster position="top-right" />
            <div className="container mx-auto py-4 sm:py-10 flex flex-col gap-6">
                <header className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-8 w-8 text-primary">
                            <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <path d="m14 14-4 4 4-4-4-4 4 4z"></path>
                        </svg>
                        <h1 className="text-2xl font-bold">xray-knife UI</h1>
                    </div>
                    <Badge className={`capitalize ${getProxyStatusColor(proxyStatus)}`}>
                        {proxyStatus}
                    </Badge>
                </header>

                <Breadcrumb>
                    <BreadcrumbList>
                        <BreadcrumbItem><BreadcrumbLink href="/">Home</BreadcrumbLink></BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem><BreadcrumbPage>Dashboard</BreadcrumbPage></BreadcrumbItem>
                    </BreadcrumbList>
                </Breadcrumb>

                <Tabs defaultValue="proxy" className="w-full">
                    <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="proxy"><Server className="mr-2 h-4 w-4" />Proxy Service</TabsTrigger>
                        <TabsTrigger value="http-tester"><Globe className="mr-2 h-4 w-4" />HTTP Tester</TabsTrigger>
                        <TabsTrigger value="cf-scanner"><Search className="mr-2 h-4 w-4" />CF Scanner</TabsTrigger>
                    </TabsList>
                    <TabsContent value="proxy" className="mt-4">
                        <ProxyTab status={proxyStatus} setStatus={setProxyStatus} />
                    </TabsContent>
                    <TabsContent value="http-tester" className="mt-4">
                        <HttpTesterTab results={httpResults} setResults={setHttpResults} />
                    </TabsContent>
                    <TabsContent value="cf-scanner" className="mt-4">
                        <CfScannerTab 
                            results={scanResults} 
                            setResults={setScanResults} 
                            status={scanStatus}
                            setStatus={setScanStatus}
                        />
                    </TabsContent>
                </Tabs>

                <Card>
                    <CardHeader className="flex flex-col sm:flex-row justify-between gap-2">
                        <div className="flex flex-col gap-1.5">
                            <CardTitle>Live Logs</CardTitle>
                            <CardDescription>Real-time output from the xray-knife backend.</CardDescription>
                        </div>
                        <Button className="w-full sm:w-fit" variant="outline" size="sm" onClick={clearLogs}>
                            <TerminalSquare className="mr-2 h-4 w-4" />Clear Logs
                        </Button>
                    </CardHeader>
                    <CardContent>
                        <div ref={terminalRef} className="h-64 sm:h-[400px] w-full rounded-md border bg-muted/20 overflow-hidden" />
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}