import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ChevronDown, ChevronUp, Download, Pause, Play, Search, Trash2, ArrowDownToLine, Maximize2, Minimize2 } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useLogStore, type LogEntry, type LogLevel } from "@/stores/logStore";
import { usePersistentState } from "@/hooks/usePersistentState";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { cn, downloadText } from "@/lib/utils";
import { useT } from "@/i18n";

type Size = "closed" | "normal" | "tall";
type LevelFilter = "all" | "problems" | LogLevel;

const LEVEL_CLASS: Record<LogLevel, string> = {
    success: "text-pass",
    error: "text-fail",
    warning: "text-semi",
    info: "text-info",
    progress: "text-foreground/80",
    plain: "text-foreground/80",
};

const LEVEL_MARK: Record<LogLevel, string> = {
    success: "ok", error: "err", warning: "warn", info: "info", progress: "…", plain: "",
};

function matches(e: LogEntry, level: LevelFilter, service: string, q: string) {
    if (level === "problems" && e.level !== "error" && e.level !== "warning") return false;
    if (level !== "all" && level !== "problems" && e.level !== level) return false;
    if (service !== "all" && e.service !== service) return false;
    if (q && !e.text.toLowerCase().includes(q) && !e.service.toLowerCase().includes(q)) return false;
    return true;
}

export function LogDock() {
    const t = useT();
    const { entries, clear } = useLogStore(useShallow((s) => ({ entries: s.entries, clear: s.clear })));
    // Phones start with the dock closed: it would take a third of the screen.
    const [size, setSize] = usePersistentState<Size>("log-dock-size", window.matchMedia("(min-width: 768px)").matches ? "normal" : "closed");
    const [level, setLevel] = useState<LevelFilter>("all");
    const [service, setService] = useState("all");
    const [query, setQuery] = useState("");
    const q = useDebouncedValue(query.trim().toLowerCase(), 200);
    const [follow, setFollow] = useState(true);
    const [paused, setPaused] = useState<LogEntry[] | null>(null);

    const source = paused ?? entries;
    const services = useMemo(() => {
        const s = new Set<string>();
        for (const e of entries) if (e.service) s.add(e.service);
        return [...s].sort();
    }, [entries]);
    const visible = useMemo(() => source.filter((e) => matches(e, level, service, q)), [source, level, service, q]);
    const problems = useMemo(() => entries.reduce((n, e) => n + (e.level === "error" ? 1 : 0), 0), [entries]);

    const scrollRef = useRef<HTMLDivElement>(null);
    const virt = useVirtualizer({
        count: size === "closed" ? 0 : visible.length,
        getScrollElement: () => scrollRef.current,
        estimateSize: () => 20,
        overscan: 30,
    });

    useEffect(() => {
        if (follow && size !== "closed" && visible.length > 0) virt.scrollToIndex(visible.length - 1, { align: "end" });
    }, [visible.length, follow, size, virt]);

    const onScroll = () => {
        const el = scrollRef.current;
        if (!el) return;
        const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
        if (!atBottom && follow) setFollow(false);
        else if (atBottom && !follow) setFollow(true);
    };

    const download = () => {
        const lines = visible.map((e) => `${e.time || new Date(e.at).toTimeString().slice(0, 8)} ${e.level.padEnd(8)} ${e.service ? `[${e.service}] ` : ""}${e.text}`);
        downloadText(`xray-knife-logs-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.txt`, lines);
    };

    const open = size !== "closed";
    return (
        <section
            aria-label={t("Live logs")}
            className={cn(
                "flex shrink-0 flex-col border-t bg-card",
                size === "normal" && "h-[40dvh] md:h-44",
                size === "tall" && "h-[55dvh]",
            )}
        >
            <div className="flex flex-wrap items-center gap-2 px-3 py-1.5">
                <button
                    type="button"
                    className="flex items-center gap-2 rounded px-1 text-sm font-medium hover:text-primary focus-visible:outline-2"
                    aria-expanded={open}
                    onClick={() => setSize(open ? "closed" : "normal")}
                >
                    {open ? <ChevronDown className="size-4" aria-hidden /> : <ChevronUp className="size-4" aria-hidden />}
                    {t("Logs")}
                    <span className="num text-xs font-normal text-muted-foreground">{entries.length}</span>
                    {problems > 0 && <span className="num rounded bg-fail/10 px-1.5 text-xs font-normal text-fail">{t("{n} errors", { n: problems })}</span>}
                </button>
                {open && (
                    <>
                        <div className="relative ms-auto w-full max-w-56 min-w-32 sm:w-56">
                            <Search className="pointer-events-none absolute start-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Filter logs")} aria-label={t("Filter logs")} className="h-7 ps-7 text-xs" />
                        </div>
                        <Select value={level} onValueChange={(v) => setLevel(v as LevelFilter)}>
                            <SelectTrigger size="sm" className="h-7 w-auto min-w-24 text-xs" aria-label={t("Level")}><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">{t("All levels")}</SelectItem>
                                <SelectItem value="problems">{t("Errors and warnings")}</SelectItem>
                                <SelectItem value="error">{t("Errors")}</SelectItem>
                                <SelectItem value="warning">{t("Warnings")}</SelectItem>
                                <SelectItem value="success">{t("Success")}</SelectItem>
                                <SelectItem value="info">{t("Info")}</SelectItem>
                            </SelectContent>
                        </Select>
                        {services.length > 0 && (
                            <Select value={service} onValueChange={setService}>
                                <SelectTrigger size="sm" className="h-7 w-auto min-w-24 text-xs" aria-label={t("Service")}><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="all">{t("All services")}</SelectItem>
                                    {services.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                                </SelectContent>
                            </Select>
                        )}
                        <div className="flex items-center">
                            <Button variant="ghost" size="icon-sm" onClick={() => setPaused(paused ? null : entries)} aria-label={paused ? t("Resume live logs") : t("Pause live logs")} title={paused ? t("Resume") : t("Pause")}>
                                {paused ? <Play aria-hidden /> : <Pause aria-hidden />}
                            </Button>
                            <Button variant="ghost" size="icon-sm" onClick={download} disabled={visible.length === 0} aria-label={t("Download logs")} title={t("Download")}>
                                <Download aria-hidden />
                            </Button>
                            <Button variant="ghost" size="icon-sm" onClick={() => { clear(); setPaused(null); }} disabled={entries.length === 0} aria-label={t("Clear logs")} title={t("Clear")}>
                                <Trash2 aria-hidden />
                            </Button>
                            <Button variant="ghost" size="icon-sm" onClick={() => setSize(size === "tall" ? "normal" : "tall")} aria-label={size === "tall" ? t("Shrink logs") : t("Enlarge logs")} title={size === "tall" ? t("Shrink") : t("Enlarge")}>
                                {size === "tall" ? <Minimize2 aria-hidden /> : <Maximize2 aria-hidden />}
                            </Button>
                        </div>
                    </>
                )}
            </div>
            {open && (
                <div className="relative min-h-0 flex-1">
                    <div
                        ref={scrollRef}
                        onScroll={onScroll}
                        className="h-full overflow-auto border-t bg-background/60 font-mono text-[12px] leading-5"
                        role="log"
                        aria-live="off"
                        dir="ltr"
                    >
                        {visible.length === 0 ? (
                            <p dir="auto" className="p-3 text-start text-muted-foreground">{entries.length === 0 ? t("Waiting for server output…") : t("No lines match the filter.")}</p>
                        ) : (
                            <div style={{ height: virt.getTotalSize(), position: "relative" }}>
                                {virt.getVirtualItems().map((row) => {
                                    const e = visible[row.index];
                                    return (
                                        <div
                                            key={e.id}
                                            data-index={row.index}
                                            ref={virt.measureElement}
                                            className="absolute inset-x-0 flex gap-2 px-3 hover:bg-accent/40"
                                            style={{ transform: `translateY(${row.start}px)` }}
                                        >
                                            <span className="num shrink-0 text-muted-foreground">{e.time}</span>
                                            <span className={cn("w-8 shrink-0", LEVEL_CLASS[e.level])}>{LEVEL_MARK[e.level]}</span>
                                            {e.service && <span className="shrink-0 text-muted-foreground">[{e.service}]</span>}
                                            <span className={cn("min-w-0 whitespace-pre-wrap break-all", LEVEL_CLASS[e.level])}>{e.text}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                    {(!follow || paused) && visible.length > 0 && (
                        <Button size="sm" variant="secondary" className="absolute bottom-2 end-4 h-7 shadow" onClick={() => { setPaused(null); setFollow(true); virt.scrollToIndex(visible.length - 1, { align: "end" }); }}>
                            <ArrowDownToLine aria-hidden />{paused ? t("Resume and jump to latest") : t("Jump to latest")}
                        </Button>
                    )}
                </div>
            )}
        </section>
    );
}
