import { useMemo, useRef, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ClipboardList, Download, Search, Trash2, ChevronDown, Radar, SearchX, Link2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuLabel, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Panel } from "@/components/common/Panel";
import { SortHeader, type SortDir } from "@/components/common/SortHeader";
import { CopyButton } from "@/components/common/CopyButton";
import { ConfirmDialog } from "@/components/common/ConfirmButton";
import { EmptyState } from "@/components/common/EmptyState";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useSettingsStore } from "@/stores/settingsStore";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import type { ScanResult } from "@/types/dashboard";
import { replaceAddress } from "@/lib/links";
import { copyText, downloadCSV, downloadJSON, downloadText, errorMessage, formatCount, formatMbps, formatMs, cn } from "@/lib/utils";
import { useT } from "@/i18n";

type SortField = "ip" | "latency" | "download" | "upload";
const ROW_H = 44;

export function CfResults({ onClear }: { onClear: () => void }) {
    const t = useT();
    const { results, status, failed } = useRuntimeStore(useShallow((s) => ({ results: s.scanResults, status: s.scanStatus, failed: s.scanFailed })));
    const template = useSettingsStore((s) => s.cfScannerSettings.advancedOptions.configLink.trim());
    const busy = status !== "idle";
    const [sort, setSort] = useState<{ field: SortField; dir: SortDir }>({ field: "latency", dir: "asc" });
    const [query, setQuery] = useState("");
    const q = useDebouncedValue(query.trim(), 200);
    const [onlySpeed, setOnlySpeed] = useState(false);
    const [confirmClear, setConfirmClear] = useState(false);

    const speedCount = useMemo(() => results.reduce((n, r) => n + (r.download_mbps > 0 || r.upload_mbps > 0 ? 1 : 0), 0), [results]);
    // The filter only applies while speed results exist, so it can't hide everything.
    const speedFilter = onlySpeed && speedCount > 0;

    const shown = useMemo(() => {
        const dir = sort.dir === "asc" ? 1 : -1;
        return results
            .filter((r) => (!speedFilter || r.download_mbps > 0 || r.upload_mbps > 0) && (!q || r.ip.includes(q) || (r.colo ?? "").toLowerCase().includes(q.toLowerCase())))
            .sort((a, b) => {
                switch (sort.field) {
                    case "ip": return a.ip.localeCompare(b.ip, undefined, { numeric: true }) * dir;
                    case "latency": return (a.latency_ms - b.latency_ms) * dir;
                    case "download": return (a.download_mbps - b.download_mbps) * dir || a.latency_ms - b.latency_ms;
                    case "upload": return (a.upload_mbps - b.upload_mbps) * dir || a.latency_ms - b.latency_ms;
                }
            });
    }, [results, speedFilter, q, sort]);

    const best = useMemo(() => results.reduce<ScanResult | null>((b, r) => (!b || r.latency_ms < b.latency_ms ? r : b), null), [results]);
    // Bars are relative to the slowest responder, so small differences stay visible.
    const slowest = useMemo(() => results.reduce((m, r) => Math.max(m, r.latency_ms), 0), [results]);
    const onSort = (field: SortField) => setSort((s) => (s.field === field ? { field, dir: s.dir === "asc" ? "desc" : "asc" } : { field, dir: field === "download" || field === "upload" ? "desc" : "asc" }));

    const scrollRef = useRef<HTMLDivElement>(null);
    const virt = useVirtualizer({ count: shown.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_H, overscan: 16 });
    const items = virt.getVirtualItems();
    const padTop = items.length ? items[0].start : 0;
    const padBottom = items.length ? virt.getTotalSize() - items[items.length - 1].end : 0;

    const copy = async (text: string, what: string) => {
        try {
            await copyText(text);
            toast.success(t("Copied {what}", { what }));
        } catch (err) {
            toast.error(t("Could not copy"), { description: errorMessage(err) });
        }
    };

    const configsFor = (rows: ScanResult[]) => rows.map((r) => replaceAddress(template, r.ip)).filter((x): x is string => !!x);
    const templateOk = template !== "" && replaceAddress(template, "1.1.1.1") !== null;

    const exportAs = (kind: "csv" | "json" | "txt") => {
        const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
        if (kind === "txt") return downloadText(`cf-ips-${stamp}.txt`, shown.map((r) => r.ip));
        if (kind === "json") return downloadJSON(`cf-scan-${stamp}.json`, shown);
        downloadCSV(`cf-scan-${stamp}.csv`, ["ip", "latency_ms", "download_mbps", "upload_mbps", "colo"],
            shown.map((r) => [r.ip, r.latency_ms, r.download_mbps || null, r.upload_mbps || null, r.colo ?? ""]));
    };

    return (
        <Panel
            title={t("Responsive IPs")}
            description={results.length === 0 ? t("IPs that answer appear here, fastest first.") : t("{n} answered{failed}, best {best}", {
                n: formatCount(results.length),
                failed: failed > 0 ? t(", {n} did not", { n: formatCount(failed) }) : "",
                best: best ? `${best.ip} (${formatMs(best.latency_ms)})` : "—",
            })}
            actions={
                <>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" size="sm" disabled={shown.length === 0}><ClipboardList aria-hidden />{t("Copy")}<ChevronDown aria-hidden className="opacity-60" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem onSelect={() => copy(shown.slice(0, 10).map((r) => r.ip).join("\n"), t("the 10 best IPs"))}>{t("Best 10 IPs")}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => copy(shown.map((r) => r.ip).join("\n"), t("{n} IPs", { n: shown.length }))}>{t("All IPs shown ({n})", { n: shown.length })}</DropdownMenuItem>
                            {templateOk && (
                                <>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuLabel>{t("Your config with these IPs")}</DropdownMenuLabel>
                                    <DropdownMenuItem onSelect={() => copy(configsFor(shown.slice(0, 10)).join("\n"), t("10 configs"))}><Link2 aria-hidden />{t("Configs for the best 10")}</DropdownMenuItem>
                                    <DropdownMenuItem onSelect={() => copy(configsFor(shown).join("\n"), t("{n} configs", { n: shown.length }))}><Link2 aria-hidden />{t("Configs for all shown")}</DropdownMenuItem>
                                </>
                            )}
                        </DropdownMenuContent>
                    </DropdownMenu>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" size="sm" disabled={shown.length === 0}><Download aria-hidden />{t("Export")}<ChevronDown aria-hidden className="opacity-60" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem onSelect={() => exportAs("csv")}>{t("CSV for spreadsheets")}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => exportAs("json")}>{t("JSON with all fields")}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => exportAs("txt")}>{t("IPs only (.txt)")}</DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                    <Button variant="ghost" size="icon-sm" disabled={busy || (results.length === 0 && failed === 0)} onClick={() => setConfirmClear(true)} aria-label={t("Clear results")} title={t("Clear results")}>
                        <Trash2 aria-hidden />
                    </Button>
                </>
            }
            bodyClassName="p-0"
            className="@container"
        >
            <div className="flex flex-wrap items-center gap-3 border-b px-3 py-2">
                {speedCount > 0 && (
                    <div className="flex items-center gap-2">
                        <Checkbox id="cf-only-speed" checked={onlySpeed} onCheckedChange={(c) => setOnlySpeed(Boolean(c))} />
                        <Label htmlFor="cf-only-speed" className="cursor-pointer text-xs font-normal">{t("Only speed-tested ({n})", { n: speedCount })}</Label>
                    </div>
                )}
                <div className="relative ms-auto w-full @lg:w-56">
                    <Search className="pointer-events-none absolute start-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                    <Input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Search IP")} aria-label={t("Search IP")} className="h-8 ps-7 text-xs" dir="ltr" />
                </div>
            </div>
            <div ref={scrollRef} className="max-h-[calc(100dvh-20rem)] min-h-72 overflow-auto">
                <table className="w-full table-fixed border-collapse text-sm">
                    <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0_var(--border)]">
                        <tr>
                            <SortHeader field="ip" active={sort.field} dir={sort.dir} onSort={onSort}>{t("IP")}</SortHeader>
                            <SortHeader field="latency" active={sort.field} dir={sort.dir} onSort={onSort} className="w-[7.5rem]">{t("Latency")}</SortHeader>
                            <SortHeader field="download" active={sort.field} dir={sort.dir} onSort={onSort} className="hidden w-[7.5rem] @lg:table-cell">{t("Download")}</SortHeader>
                            <SortHeader field="upload" active={sort.field} dir={sort.dir} onSort={onSort} className="hidden w-[7.5rem] @lg:table-cell">{t("Upload")}</SortHeader>
                            <th scope="col" className="w-[4.5rem]"><span className="sr-only">{t("Actions")}</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        {shown.length === 0 ? (
                            <tr><td colSpan={5}>
                                {results.length === 0
                                    ? <EmptyState icon={Radar} title={busy ? t("Scanning… responsive IPs show up here") : t("No results yet")}>{!busy && t("Load the Cloudflare ranges or paste your own, then start a scan.")}</EmptyState>
                                    : <EmptyState icon={SearchX} title={t("No IPs match the filter")} />}
                            </td></tr>
                        ) : (
                            <>
                                {padTop > 0 && <tr aria-hidden><td colSpan={5} style={{ height: padTop, padding: 0 }} /></tr>}
                                {items.map((row) => {
                                    const r = shown[row.index];
                                    const frac = Math.min(r.latency_ms / Math.max(slowest, 1), 1);
                                    const cfg = templateOk ? replaceAddress(template, r.ip) : null;
                                    return (
                                        <tr key={r.ip} className="h-11 border-b border-border/60 hover:bg-accent/40">
                                            <td className="truncate px-2 font-mono text-[12.5px]" dir="ltr">{r.ip}{r.colo && <span className="ms-2 font-sans text-xs text-muted-foreground">{r.colo}</span>}</td>
                                            <td className="px-2">
                                                <div className="num text-[13px] font-medium">{formatMs(r.latency_ms)}</div>
                                                <div className="trace mt-1 max-w-24" style={{ "--w": frac } as React.CSSProperties} aria-hidden />
                                            </td>
                                            <td className={cn("num hidden px-2 text-xs @lg:table-cell", !r.download_mbps && "text-muted-foreground")}>{r.speed_error ? <span className="text-fail" title={r.speed_error}>{t("failed")}</span> : formatMbps(r.download_mbps)}</td>
                                            <td className={cn("num hidden px-2 text-xs @lg:table-cell", !r.upload_mbps && "text-muted-foreground")}>{formatMbps(r.upload_mbps)}</td>
                                            <td className="px-1">
                                                <div className="flex justify-end">
                                                    <CopyButton text={r.ip} label={t("Copy IP")} done={t("IP copied")} />
                                                    {cfg && <CopyButton text={cfg} label={t("Copy your config with this IP")} done={t("Config copied")} className="[&_svg]:text-primary" />}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                                {padBottom > 0 && <tr aria-hidden><td colSpan={5} style={{ height: padBottom, padding: 0 }} /></tr>}
                            </>
                        )}
                    </tbody>
                </table>
            </div>
            <ConfirmDialog open={confirmClear} onOpenChange={setConfirmClear} title={t("Clear scan results?")}
                description={t("This deletes the saved scan results, so Resume starts from scratch.")} confirmLabel={t("Clear")} onConfirm={onClear} />
        </Panel>
    );
}
