import { useEffect, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { Globe, Server, Radar, Rss, History, Settings, ScanSearch, Menu, PanelLeftClose, PanelLeftOpen, LogOut, Sun, Moon, Monitor, WifiOff, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { BrandMark } from "./BrandMark";
import { StatusStrip } from "./StatusStrip";
import { LogDock } from "./LogDock";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useServerStore } from "@/stores/serverStore";
import { useTheme } from "@/components/theme-provider";
import { usePersistentState } from "@/hooks/usePersistentState";
import { useNow } from "@/hooks/useNow";
import type { Page } from "@/hooks/useHashRoute";
import { events } from "@/services/events";
import { cn } from "@/lib/utils";
import { useI18n } from "@/i18n";

interface NavItem {
    id: Page;
    label: string;
    icon: typeof Globe;
    show?: boolean | null;
}

function ConnectionBanner() {
    const { t } = useI18n();
    const { sse, retryAt, synced } = useRuntimeStore(useShallow((s) => ({ sse: s.sse, retryAt: s.sseRetryAt, synced: s.synced })));
    const [visible, setVisible] = useState(false);
    const now = useNow(1000, sse === "reconnecting");
    // Brief blips are normal; only speak up after a few seconds.
    useEffect(() => {
        if (sse !== "reconnecting") { setVisible(false); return; }
        const id = window.setTimeout(() => setVisible(true), 3000);
        return () => window.clearTimeout(id);
    }, [sse]);
    if (!visible || !synced) return null;
    const secs = retryAt ? Math.max(0, Math.ceil((retryAt - now) / 1000)) : 0;
    return (
        <div role="status" className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-semi/30 bg-semi/10 px-4 py-1.5 text-xs">
            <WifiOff className="size-3.5 text-semi" aria-hidden />
            <span>{t("Lost the live connection to the server. Status and results on screen may be out of date.")}</span>
            <span className="num text-muted-foreground">{secs > 0 ? t("Retrying in {n} s", { n: secs }) : t("Retrying…")}</span>
            <Button size="sm" variant="outline" className="ms-auto h-6 px-2 text-xs" onClick={() => events.retryNow()}>
                <RefreshCw aria-hidden />{t("Retry now")}
            </Button>
        </div>
    );
}

function LiveIndicator() {
    const { t } = useI18n();
    const sse = useRuntimeStore((s) => s.sse);
    const text = sse === "live" ? t("Live") : sse === "connecting" ? t("Connecting…") : t("Reconnecting…");
    return (
        <span className="hidden items-center gap-1.5 text-xs text-muted-foreground md:inline-flex" role="status" aria-live="polite">
            <span aria-hidden className={cn("size-2 rounded-full", sse === "live" ? "bg-pass" : "bg-semi animate-pulse")} />
            {text}
        </span>
    );
}

export function AppShell({ page, navigate, onLogout, children }: { page: Page; navigate: (p: Page) => void; onLogout?: () => void; children: React.ReactNode }) {
    const { t, dir } = useI18n();
    const [collapsed, setCollapsed] = usePersistentState("sidebar-collapsed", false);
    const [mobileOpen, setMobileOpen] = useState(false);
    const { theme, setTheme } = useTheme();
    const { hasSubscriptions, hasHistory } = useServerStore(useShallow((s) => ({ hasSubscriptions: s.hasSubscriptions, hasHistory: s.hasHistory })));
    const activity = useRuntimeStore(useShallow((s) => ({
        proxy: s.proxyStatus === "running" ? "on" : s.proxyStatus === "stopped" ? null : "busy",
        http: s.httpStatus === "idle" ? null : "busy",
        cf: s.scanStatus === "idle" ? null : "busy",
        dpi: s.dpiStatus === "idle" ? null : "busy",
    }) as Partial<Record<Page, "on" | "busy" | null>>));

    const items: NavItem[] = [
        { id: "proxy", label: t("Proxy"), icon: Server },
        { id: "http", label: t("HTTP tester"), icon: Globe },
        { id: "cf", label: t("CF scanner"), icon: Radar },
        { id: "dpi", label: t("DPI finder"), icon: ScanSearch },
        { id: "subscriptions", label: t("Subscriptions"), icon: Rss, show: hasSubscriptions },
        { id: "history", label: t("History"), icon: History, show: hasHistory },
        { id: "settings", label: t("Settings"), icon: Settings },
    ].filter((i) => i.show !== false) as NavItem[];
    const current = items.find((i) => i.id === page);

    const nextTheme = theme === "system" ? "light" : theme === "light" ? "dark" : "system";
    const ThemeIcon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
    const themeName = { system: t("system"), light: t("light"), dark: t("dark") }[theme];

    const nav = (compact: boolean, onPick?: () => void) => (
        <ul className="flex flex-col gap-0.5">
            {items.map((item) => {
                const active = item.id === page;
                return (
                    <li key={item.id}>
                        <a
                            href={`#/${item.id}`}
                            onClick={(e) => { e.preventDefault(); navigate(item.id); onPick?.(); }}
                            aria-current={active ? "page" : undefined}
                            title={compact ? item.label : undefined}
                            className={cn(
                                "flex items-center gap-3 rounded-md px-2.5 py-2 text-sm transition-colors focus-visible:outline-2",
                                active ? "bg-primary/10 font-medium text-primary" : "text-foreground/80 hover:bg-accent hover:text-foreground",
                                compact && "justify-center px-0",
                            )}
                        >
                            <span className="relative">
                                <item.icon className="size-4 shrink-0" aria-hidden />
                                {activity[item.id] && (
                                    <span aria-hidden className={cn("absolute -end-1 -top-1 size-2 rounded-full ring-2 ring-card", activity[item.id] === "on" ? "bg-pass" : "animate-pulse bg-primary")} />
                                )}
                            </span>
                            <span className={cn(compact && "sr-only")}>{item.label}</span>
                            {activity[item.id] && <span className="sr-only">({activity[item.id] === "on" ? t("Running") : t("Working")})</span>}
                        </a>
                    </li>
                );
            })}
        </ul>
    );

    return (
        <div className={cn("grid h-dvh w-full overflow-hidden", collapsed ? "md:grid-cols-[64px_1fr]" : "md:grid-cols-[216px_1fr]")}>
            <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground">
                {t("Skip to content")}
            </a>
            <aside className="hidden min-h-0 flex-col border-e bg-card md:flex" aria-label={t("Main navigation")}>
                <div className={cn("flex h-14 items-center gap-2 border-b px-3", collapsed && "justify-center px-0")}>
                    <a href="#/proxy" onClick={(e) => { e.preventDefault(); navigate("proxy"); }} className="flex items-center gap-2 rounded focus-visible:outline-2" aria-label="xray-knife">
                        <BrandMark className="size-7" />
                        {!collapsed && <span className="text-[15px] font-semibold tracking-tight">xray-knife</span>}
                    </a>
                </div>
                <nav className="min-h-0 flex-1 overflow-y-auto p-2">{nav(collapsed)}</nav>
                <div className="border-t p-2">
                    <Button variant="ghost" size="sm" className={cn("w-full justify-start text-muted-foreground", collapsed && "justify-center")} onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? t("Expand sidebar") : t("Collapse sidebar")}>
                        {collapsed ? <PanelLeftOpen className="rtl:-scale-x-100" aria-hidden /> : <PanelLeftClose className="rtl:-scale-x-100" aria-hidden />}
                        {!collapsed && t("Collapse")}
                    </Button>
                </div>
            </aside>

            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
                <SheetContent side={dir === "rtl" ? "right" : "left"} className="w-72 p-0">
                    <div className="flex h-14 items-center gap-2 border-b px-4">
                        <BrandMark className="size-7" />
                        <SheetTitle className="text-[15px]">xray-knife</SheetTitle>
                    </div>
                    <SheetDescription className="sr-only">{t("Main navigation")}</SheetDescription>
                    <nav className="p-2">{nav(false, () => setMobileOpen(false))}</nav>
                </SheetContent>
            </Sheet>

            <div className="flex min-h-0 min-w-0 flex-col">
                <header className="flex shrink-0 flex-col border-b bg-card/80 backdrop-blur">
                    <div className="flex h-14 items-center gap-2 px-3 lg:px-5">
                        <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setMobileOpen(true)} aria-label={t("Open menu")}>
                            <Menu aria-hidden />
                        </Button>
                        <h1 className="min-w-0 truncate text-base font-semibold">{current?.label ?? "xray-knife"}</h1>
                        <div className="ms-auto hidden min-w-0 lg:block">
                            <StatusStrip page={page} navigate={navigate} />
                        </div>
                        <div className="ms-auto flex items-center gap-1 lg:ms-3">
                            <LiveIndicator />
                            <Button variant="ghost" size="icon" onClick={() => setTheme(nextTheme)} aria-label={t("Theme: {name}. Switch theme", { name: themeName })} title={t("Theme: {name}", { name: themeName })}>
                                <ThemeIcon aria-hidden />
                            </Button>
                            {onLogout && (
                                <Button variant="ghost" size="icon" onClick={onLogout} aria-label={t("Log out")} title={t("Log out")}>
                                    <LogOut className="rtl:-scale-x-100" aria-hidden />
                                </Button>
                            )}
                        </div>
                    </div>
                    <div className="border-t px-2 py-1 lg:hidden">
                        <StatusStrip page={page} navigate={navigate} />
                    </div>
                </header>
                <ConnectionBanner />
                <main id="main" tabIndex={-1} className="min-h-0 flex-1 overflow-y-auto focus:outline-none">
                    <div className="mx-auto w-full max-w-[1600px] p-3 sm:p-4 lg:p-5">{children}</div>
                </main>
                <LogDock />
            </div>
        </div>
    );
}
