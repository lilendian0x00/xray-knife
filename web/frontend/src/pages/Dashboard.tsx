import { useState, useEffect, useRef } from "react";
import { Toaster } from "@/components/ui/sonner";
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { toast } from "sonner";
import { FaCloudflare } from "react-icons/fa";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Sheet, SheetClose, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Server, Globe, Menu, Package2, PanelLeft, Search, LogOut, Trash2, ArrowDownToLine, Pause, Sun, Moon, Monitor, ChevronDown, ChevronUp } from 'lucide-react';
import { useAppStore } from "@/stores/appStore";
import { webSocketService } from "@/services/websocket";
import { ProxyTab } from "./dashboard/ProxyTab";
import { HttpTesterTab } from "./dashboard/HttpTesterTab";
import { CfScannerTab } from "./dashboard/CFScannerTab";
import { ProxyStatusCard } from "./dashboard/ProxyStatusCard";
import { type ProxyStatus } from "@/types/dashboard";
import { api } from "@/services/api";
import { useTheme } from "@/components/theme-provider";
import { usePersistentState } from "@/hooks/usePersistentState";

type Page = 'proxy' | 'http-tester' | 'cf-scanner';
const navItems = [
    { id: 'proxy' as Page, label: 'Proxy Service', icon: Server },
    { id: 'http-tester' as Page, label: 'HTTP Tester', icon: Globe },
    { id: 'cf-scanner' as Page, label: 'CF Scanner', icon: FaCloudflare }
];

export default function Dashboard() {
    const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
    const [activePage, setActivePage] = useState<Page>('proxy');
    const [isLoading, setIsLoading] = useState(true);
    const [isTerminalCollapsed, setIsTerminalCollapsed] = usePersistentState('terminal-collapsed', false);

    const {
        proxyStatus, setProxyStatus,
        proxyDetails, setProxyDetails,
        setScanStatus, setScanResults,
        setHttpResults, setHttpTestStatus,
        logout,
        wsConnected,
    } = useAppStore();

    const { theme, setTheme } = useTheme();
    const terminalRef = useRef<HTMLDivElement>(null);
    const term = useRef<Terminal | null>(null);
    const fitAddon = useRef<FitAddon | null>(null);
    const [logSearchTerm, setLogSearchTerm] = useState('');
    const [isAutoScroll, setIsAutoScroll] = useState(true);

    const cycleTheme = () => {
        const next = theme === 'system' ? 'light' : theme === 'light' ? 'dark' : 'system';
        setTheme(next);
    };

    const ThemeIcon = theme === 'light' ? Sun : theme === 'dark' ? Moon : Monitor;

    // --- Terminal Lifecycle (create once, never destroy on layout changes) ---
    useEffect(() => {
        if (terminalRef.current && !term.current) {
            const terminal = new Terminal({
                convertEol: true,
                cursorBlink: true,
                fontFamily: 'monospace',
                fontSize: 13,
                theme: { background: '#18181b', foreground: '#e4e4e7' },
            });
            const addon = new FitAddon();
            terminal.loadAddon(addon);
            terminal.open(terminalRef.current);
            setTimeout(() => addon.fit(), 1);

            term.current = terminal;
            fitAddon.current = addon;

            const resizeObserver = new ResizeObserver(() => {
                setTimeout(() => fitAddon.current?.fit(), 1);
            });
            resizeObserver.observe(terminalRef.current);

            return () => {
                resizeObserver.disconnect();
                terminal.dispose();
                term.current = null;
            };
        }
    }, []); // Create terminal only once on mount

    // Update terminal theme without re-creating the instance
    useEffect(() => {
        if (term.current) {
            const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
            term.current.options.theme = isDark
                ? { background: '#18181b', foreground: '#e4e4e7' }
                : { background: '#FFFFFF', foreground: '#09090b' };
        }
    }, [theme]);

    // Re-fit terminal when layout changes (sidebar collapse, tab switch, terminal expand)
    useEffect(() => {
        setTimeout(() => fitAddon.current?.fit(), 50);
    }, [activePage, isSidebarCollapsed, isTerminalCollapsed]);

    // Connect WebSocket once on mount
    useEffect(() => {
        webSocketService.connect();
    }, []);

    // Log listener — re-attaches only when filter/scroll settings change
    useEffect(() => {
        const logListener = (text: string) => {
            if (logSearchTerm && !text.toLowerCase().includes(logSearchTerm.toLowerCase())) {
                return;
            }
            if (term.current) {
                term.current.writeln(text);
                if (isAutoScroll) {
                    term.current.scrollToBottom();
                }
            }
        };

        webSocketService.on('log', logListener);

        return () => {
            webSocketService.off('log', logListener);
        };
    }, [logSearchTerm, isAutoScroll]);


    // --- Initial State Fetching ---
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
            } finally {
                setIsLoading(false);
            }
        };
        fetchInitialState();
    }, [setProxyStatus, setProxyDetails, setScanStatus, setScanResults, setHttpResults, setHttpTestStatus]);

    const getProxyStatusColor = (status: ProxyStatus) => {
        if (status === 'running') return 'bg-green-500 text-primary-foreground';
        if (status === 'stopped') return 'bg-destructive';
        return 'bg-yellow-500 text-destructive-foreground';
    };

    const clearLogs = () => term.current?.clear();
    const currentPageInfo = navItems.find(item => item.id === activePage);

    const logsCard = (
        <Card className="flex flex-col h-full">
            <CardHeader>
                <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex-col gap-1.5">
                        <CardTitle>Live Logs</CardTitle>
                        <CardDescription>Real-time output from the backend.</CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="relative w-full max-w-sm">
                           <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                           <Input placeholder="Filter incoming logs..." className="pl-8" value={logSearchTerm} onChange={(e) => setLogSearchTerm(e.target.value)} />
                        </div>
                        <Button variant="outline" size="icon" onClick={() => setIsAutoScroll(prev => !prev)} title={isAutoScroll ? "Disable Auto-Scroll" : "Enable Auto-Scroll"}>
                           {isAutoScroll ? <ArrowDownToLine className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
                        </Button>
                        <Button variant="outline" size="icon" onClick={clearLogs} title="Clear Logs">
                            <Trash2 className="h-4 w-4" />
                        </Button>
                        <Button variant="outline" size="icon" onClick={() => setIsTerminalCollapsed(prev => !prev)} title={isTerminalCollapsed ? "Expand Terminal" : "Collapse Terminal"}>
                            {isTerminalCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                        </Button>
                    </div>
                </div>
            </CardHeader>
            <motion.div
                animate={isTerminalCollapsed
                    ? { height: 0, opacity: 0 }
                    : { height: 'auto', opacity: 1 }}
                initial={false}
                transition={{ duration: 0.2 }}
                className="overflow-hidden flex-1 min-h-0"
            >
                <CardContent className="h-full max-w-screen pb-6">
                    <div ref={terminalRef} className="h-full w-full min-h-[200px] rounded-md border bg-muted/20 overflow-hidden" />
                </CardContent>
            </motion.div>
        </Card>
    );

    const renderPageLayout = () => {
        if (isLoading) {
            return (
                <div className="grid h-full items-start gap-4 lg:grid-cols-5 lg:gap-8">
                    <div className="grid auto-rows-max items-start gap-4 lg:col-span-2">
                        <Skeleton className="h-[400px] w-full" />
                    </div>
                    <div className="flex flex-col items-start gap-4 lg:col-span-3 h-full">
                        <Skeleton className="h-[200px] w-full" />
                        <Skeleton className="h-[300px] w-full flex-1" />
                    </div>
                </div>
            );
        }

        if (activePage === 'proxy') {
            return (
                <div className="grid h-full items-start gap-4 lg:grid-cols-5 lg:gap-8">
                    <div className="grid auto-rows-max items-start gap-4 lg:col-span-2">
                        <ProxyTab />
                    </div>
                    <div className="flex flex-col items-start gap-4 lg:col-span-3 h-full">
                        <ProxyStatusCard details={proxyDetails} />
                        <div className="flex-1 min-h-0 w-full">
                            {logsCard}
                        </div>
                    </div>
                </div>
            );
        }
        return (
            <div className="flex h-full flex-col gap-4 lg:gap-6">
                {activePage === 'http-tester' ? <HttpTesterTab /> : <CfScannerTab />}
                <div className="flex-1">
                    {logsCard}
                </div>
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
                <div className="flex flex-col overflow-hidden min-w-0">
                    <header className="flex h-14 items-center gap-4 border-b bg-muted/40 px-4 lg:h-[60px] lg:px-6">
                        <Sheet><SheetTrigger asChild><Button variant="outline" size="icon" className="shrink-0 md:hidden"><Menu className="h-5 w-5" /><span className="sr-only">Toggle menu</span></Button></SheetTrigger>
                            <SheetContent side="left" className="flex flex-col">
                                <nav className="grid gap-2 text-lg font-medium"><a href="/" className="flex items-center gap-2 text-lg font-semibold mb-4"><Package2 className="h-6 w-6 text-primary" /><span>xray-knife</span></a>{navItems.map(item => (<SheetClose asChild key={item.id}><Button variant={activePage === item.id ? "secondary" : "ghost"} className="w-full justify-start gap-2 py-6 text-base" onClick={() => setActivePage(item.id)}><item.icon className="h-5 w-5" />{item.label}</Button></SheetClose>))}</nav>
                            </SheetContent>
                        </Sheet>
                        <div className="w-full flex-1"><Breadcrumb><BreadcrumbList><BreadcrumbItem><BreadcrumbLink href="/">Home</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbPage>{currentPageInfo?.label}</BreadcrumbPage></BreadcrumbItem></BreadcrumbList></Breadcrumb></div>
                        <div className="flex items-center gap-1" title={wsConnected ? "WebSocket Connected" : "WebSocket Disconnected"}>
                            <span className={cn("size-2 rounded-full", wsConnected ? "bg-green-500" : "bg-red-500")} />
                        </div>
                        <Badge className={cn("capitalize", getProxyStatusColor(proxyStatus))}>Proxy: {proxyStatus}</Badge>
                        <Button variant="ghost" size="icon" onClick={cycleTheme} title={`Theme: ${theme}`}>
                            <ThemeIcon className="h-5 w-5" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={logout} title="Logout"><LogOut className="h-5 w-5" /></Button>
                    </header>
                    <main className="flex-1 overflow-auto p-4 lg:p-6 min-w-0">
                        <div className="mx-auto h-full w-full max-w-screen-2xl">
                            <AnimatePresence mode="wait">
                                <motion.div
                                    key={activePage}
                                    initial={{ opacity: 0, y: 8 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -8 }}
                                    transition={{ duration: 0.15 }}
                                    className="h-full"
                                >
                                    {renderPageLayout()}
                                </motion.div>
                            </AnimatePresence>
                        </div>
                    </main>
                </div>
            </div>
        </>
    );
}
