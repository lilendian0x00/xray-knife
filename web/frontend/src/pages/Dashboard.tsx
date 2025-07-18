import { useState, useEffect, useRef } from "react";
import { Toaster } from "@/components/ui/sonner";
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { toast } from "sonner";
import { FaCloudflare } from "react-icons/fa";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Sheet, SheetClose, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Server, Globe, TerminalSquare, Menu, Package2, PanelLeft } from 'lucide-react';
import { useAppStore } from "@/stores/appStore";
import { webSocketService } from "@/services/websocket";
import { ProxyTab } from "./dashboard/ProxyTab";
import { HttpTesterTab } from "./dashboard/HttpTesterTab";
import { CfScannerTab } from "./dashboard/CFScannerTab";
import { ProxyStatusCard } from "./dashboard/ProxyStatusCard";
import { type ProxyStatus } from "@/types/dashboard";
import { api } from "@/services/api";

type Page = 'proxy' | 'http-tester' | 'cf-scanner';
const navItems = [
    { id: 'proxy' as Page, label: 'Proxy Service', icon: Server },
    { id: 'http-tester' as Page, label: 'HTTP Tester', icon: Globe },
    { id: 'cf-scanner' as Page, label: 'CF Scanner', icon: FaCloudflare }
];

export default function Dashboard() {
    const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
    const [activePage, setActivePage] = useState<Page>('proxy');
    
    const { 
        proxyStatus, setProxyStatus, 
        proxyDetails, setProxyDetails,
        setScanStatus, setScanResults, 
        setHttpResults, setHttpTestStatus 
    } = useAppStore();

    const terminalRef = useRef<HTMLDivElement>(null);
    const term = useRef<Terminal | null>(null);
    const fitAddon = useRef<FitAddon | null>(null);

    useEffect(() => {
        if (terminalRef.current && !term.current) {
            const terminal = new Terminal({ convertEol: true, cursorBlink: true, fontFamily: 'monospace', theme: { background: '#18181b', foreground: '#e4e4e7' } });
            const addon = new FitAddon();
            terminal.loadAddon(addon);
            terminal.open(terminalRef.current);
            addon.fit();
            term.current = terminal;
            fitAddon.current = addon;
            webSocketService.connect({ writeln: (text) => term.current?.writeln(text) });
            const resizeHandler = () => fitAddon.current?.fit();
            window.addEventListener('resize', resizeHandler);
            return () => { 
                window.removeEventListener('resize', resizeHandler); 
                webSocketService.disconnect(); 
                term.current?.dispose(); 
            };
        }
    }, []);

    useEffect(() => {
        const fetchInitialState = async () => {
            try {
                const [scanStatusRes, scanHistoryRes, proxyStatusRes, httpHistoryRes, httpTestStatusRes] = await Promise.all([
                    api.getCfScannerStatus(), 
                    api.getCfScannerHistory(), 
                    api.getProxyStatus(),
                    api.getHttpTestHistory(),
                    api.getHttpTestStatus(),
                ]);

                if (scanStatusRes.data.is_scanning) { 
                    setScanStatus('running'); 
                    toast.info("A scan is already in progress."); 
                }
                if (scanHistoryRes.data && Array.isArray(scanHistoryRes.data)) setScanResults(scanHistoryRes.data);
                
                if (proxyStatusRes.data.status) {
                    const status = proxyStatusRes.data.status as ProxyStatus;
                    setProxyStatus(status);
                    if (status === 'running') {
                        const detailsRes = await api.getProxyDetails();
                        setProxyDetails(detailsRes.data);
                        toast.info("Proxy service is running.");
                    }
                }
                
                if (httpTestStatusRes.data.status && httpTestStatusRes.data.status !== 'idle') {
                    setHttpTestStatus(httpTestStatusRes.data.status as any);
                    toast.info("An HTTP test is already in progress.");
                }
                if (httpHistoryRes.data && Array.isArray(httpHistoryRes.data)) {
                    setHttpResults(httpHistoryRes.data);
                }
            } catch (error) { 
                toast.error("Could not fetch initial server state."); 
            }
        };
        fetchInitialState();
    }, [setProxyStatus, setProxyDetails, setScanStatus, setScanResults, setHttpResults, setHttpTestStatus]);

    useEffect(() => { 
        const timer = setTimeout(() => fitAddon.current?.fit(), 100); 
        return () => clearTimeout(timer); 
    }, [activePage, isSidebarCollapsed]);

    const getProxyStatusColor = (status: ProxyStatus) => {
        if (status === 'running') return 'bg-green-500 text-primary-foreground';
        if (status === 'stopped') return 'bg-destructive';
        return 'bg-yellow-500 text-destructive-foreground';
    };

    const clearLogs = () => term.current?.clear();
    const currentPageInfo = navItems.find(item => item.id === activePage);

    const logsCard = (
        <Card>
            <CardHeader className="flex-row items-center justify-between">
                <div className="flex-col gap-1.5"><CardTitle>Live Logs</CardTitle><CardDescription>Real-time output from the backend.</CardDescription></div>
                <Button variant="outline" size="sm" onClick={clearLogs}><TerminalSquare className="mr-2 h-4 w-4" />Clear</Button>
            </CardHeader>
            <CardContent><div ref={terminalRef} className="h-64 sm:h-[400px] w-full rounded-md border bg-muted/20 overflow-hidden" /></CardContent>
        </Card>
    );

    const renderPageLayout = () => {
        if (activePage === 'proxy') {
            return (
                <div className="grid items-start gap-4 lg:grid-cols-5 lg:gap-8">
                    <div className="grid auto-rows-max items-start gap-4 lg:col-span-2"><ProxyTab /></div>
                    <div className="grid auto-rows-max items-start gap-4 lg:col-span-3">
                        <ProxyStatusCard details={proxyDetails} />
                        <div className={cn(proxyDetails === null && 'hidden')} >{logsCard}</div>
                    </div>
                </div>
            );
        }
        return (
            <div className="flex flex-col gap-4 lg:gap-6">
                {activePage === 'http-tester' ? <HttpTesterTab /> : <CfScannerTab />}
                {logsCard}
            </div>
        );
    };

    return (
        <>
            <Toaster position="top-right" />
            <div className={cn("grid h-screen w-full transition-[grid-template-columns]", isSidebarCollapsed ? "md:grid-cols-[68px_1fr]" : "md:grid-cols-[220px_1fr] lg:grid-cols-[280px_1fr]")}>
                <div className="hidden border-r bg-muted/40 md:block">
                    <div className="flex h-full max-h-screen flex-col">
                        {isSidebarCollapsed ? (
                            <div className="flex h-14 items-center justify-center border-b px-2 lg:h-[60px]"><Button variant="ghost" size="icon" className="group" onClick={() => setIsSidebarCollapsed(false)}><Package2 className="h-6 w-6 text-primary" /><span className="sr-only">Expand</span></Button></div>
                        ) : (
                            <div className="flex h-14 items-center justify-between border-b px-4 lg:h-[60px] lg:px-6"><a href="/" className="flex items-center gap-2 font-semibold"><Package2 className="h-6 w-6 text-primary" /><span>xray-knife</span></a><Button variant="ghost" size="icon" onClick={() => setIsSidebarCollapsed(true)}><PanelLeft className="h-5 w-5" /><span className="sr-only">Collapse</span></Button></div>
                        )}
                        <div className="flex-1 overflow-auto"><nav className={cn("grid items-start gap-1 mt-2", isSidebarCollapsed ? "px-2" : "px-2 lg:px-4")}>{navItems.map(item => (<Button key={item.id} variant={activePage === item.id ? "default" : "ghost"} className={cn("w-full gap-2", isSidebarCollapsed ? "justify-center" : "justify-start")} onClick={() => setActivePage(item.id)}><item.icon className="h-4 w-4" /><span className={cn(isSidebarCollapsed && "sr-only")}>{item.label}</span></Button>))}</nav></div>
                    </div>
                </div>
                <div className="flex flex-col">
                    <header className="flex h-14 items-center gap-4 border-b bg-muted/40 px-4 lg:h-[60px] lg:px-6">
                        <Sheet><SheetTrigger asChild><Button variant="outline" size="icon" className="shrink-0 md:hidden"><Menu className="h-5 w-5" /><span className="sr-only">Toggle menu</span></Button></SheetTrigger>
                            <SheetContent side="left" className="flex flex-col">
                                <nav className="grid gap-2 text-lg font-medium"><a href="/" className="flex items-center gap-2 text-lg font-semibold mb-4"><Package2 className="h-6 w-6 text-primary" /><span>xray-knife</span></a>{navItems.map(item => (<SheetClose asChild key={item.id}><Button variant={activePage === item.id ? "secondary" : "ghost"} className="w-full justify-start gap-2 py-6 text-base" onClick={() => setActivePage(item.id)}><item.icon className="h-5 w-5" />{item.label}</Button></SheetClose>))}</nav>
                            </SheetContent>
                        </Sheet>
                        <div className="w-full flex-1"><Breadcrumb><BreadcrumbList><BreadcrumbItem><BreadcrumbLink href="/">Home</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbPage>{currentPageInfo?.label}</BreadcrumbPage></BreadcrumbItem></BreadcrumbList></Breadcrumb></div>
                        <Badge className={cn("capitalize", getProxyStatusColor(proxyStatus))}>Proxy: {proxyStatus}</Badge>
                    </header>
                    <main className="flex-1 overflow-auto p-4 lg:p-6"><div className="mx-auto w-full max-w-screen-2xl">{renderPageLayout()}</div></main>
                </div>
            </div>
        </>
    );
}