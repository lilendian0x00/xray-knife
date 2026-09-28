import { useMemo, useRef, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ClipboardList, Download, Search, Trash2, RotateCw, QrCode, Info, ChevronDown, Globe, SearchX } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuLabel, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Panel } from "@/components/common/Panel";
import { ResultStatusBadge } from "@/components/common/StatusBadge";
import { SortHeader, type SortDir } from "@/components/common/SortHeader";
import { CopyButton } from "@/components/common/CopyButton";
import { ConfirmDialog } from "@/components/common/ConfirmButton";
import { EmptyState } from "@/components/common/EmptyState";
import { QrDialog } from "@/components/common/QrDialog";
import { ResultDetails } from "./ResultDetails";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useSettingsStore } from "@/stores/settingsStore";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import type { HttpResult } from "@/types/dashboard";
import { cn, copyText, downloadCSV, downloadJSON, downloadText, errorMessage, formatCount, formatMbps, formatMs } from "@/lib/utils";
import { cleanIp, cleanLocation, compareResults, failureLabel, FAILURE_KINDS, flag, hasDelay, isWorking, resultName, resultProtocol, type SortField } from "./resultUtils";
import { useT } from "@/i18n";

type StatusFilter = "all" | "working" | "passed" | "semi-passed" | "failed";

const ROW_H = 52;

interface HttpResultsProps {
    onRetest: (links: string[]) => void;
    onClear: () => void;
}

export function HttpResults({ onRetest, onClear }: HttpResultsProps) {
    const t = useT();
    const { results, status } = useRuntimeStore(useShallow((s) => ({ results: s.httpResults, status: s.httpStatus })));
    const maxDelay = useSettingsStore((s) => s.httpSettings.maxDelay);
    const busy = status !== "idle";

    const [sort, setSort] = useState<{ field: SortField; dir: SortDir }>({ field: "delay", dir: "asc" });
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
    const [protocol, setProtocol] = useState("all");
    const [kind, setKind] = useState<string | null>(null);
    const [query, setQuery] = useState("");
    const q = useDebouncedValue(query.trim().toLowerCase(), 200);
    const [detail, setDetail] = useState<HttpResult | null>(null);
    const [qrLink, setQrLink] = useState<string | null>(null);
    const [confirmClear, setConfirmClear] = useState(false);

    const counts = useMemo(() => {
        const c = { passed: 0, semi: 0, failed: 0 };
        for (const r of results) {
            if (r.status === "passed") c.passed++;
            else if (r.status === "semi-passed") c.semi++;
            else c.failed++;
        }
        return c;
    }, [results]);

    const protocols = useMemo(() => [...new Set(results.map(resultProtocol))].sort(), [results]);
    const kinds = useMemo(() => {
        const m = new Map<string, number>();
        for (const r of results) if (!isWorking(r) && r.failureKind) m.set(r.failureKind, (m.get(r.failureKind) ?? 0) + 1);
        return [...m.entries()].sort((a, b) => b[1] - a[1]);
    }, [results]);

    const shown = useMemo(() => {
        const dir = sort.dir === "asc" ? 1 : -1;
        return results
            .filter((r) => {
                if (statusFilter === "working" && !isWorking(r)) return false;
                if (statusFilter === "passed" && r.status !== "passed") return false;
                if (statusFilter === "semi-passed" && r.status !== "semi-passed") return false;
                if (statusFilter === "failed" && isWorking(r)) return false;
                if (protocol !== "all" && resultProtocol(r) !== protocol) return false;
                if (kind && r.failureKind !== kind) return false;
                if (q) {
                    const hay = `${resultName(r)} ${r.link} ${cleanIp(r.ip)} ${r.location} ${r.colo ?? ""} ${r.reason} ${failureLabel(r.failureKind)}`.toLowerCase();
                    if (!hay.includes(q)) return false;
                }
                return true;
            })
            .sort((a, b) => compareResults(a, b, sort.field, dir as 1 | -1));
    }, [results, statusFilter, protocol, kind, q, sort]);

    const onSort = (field: SortField) =>
        setSort((s) => (s.field === field ? { field, dir: s.dir === "asc" ? "desc" : "asc" } : { field, dir: field === "download" || field === "upload" ? "desc" : "asc" }));

    const scrollRef = useRef<HTMLDivElement>(null);
    const virt = useVirtualizer({ count: shown.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_H, overscan: 12 });
    const items = virt.getVirtualItems();
    const padTop = items.length ? items[0].start : 0;
    const padBottom = items.length ? virt.getTotalSize() - items[items.length - 1].end : 0;

    const copyLinks = async (list: HttpResult[], what: string) => {
        if (list.length === 0) { toast.info(t("Nothing to copy")); return; }
        try {
            await copyText(list.map((r) => r.link).join("\n"));
            toast.success(t("Copied {n} {what}", { n: list.length, what }));
        } catch (err) {
            toast.error(t("Could not copy"), { description: errorMessage(err) });
        }
    };

    const exportAs = (kind: "csv" | "json" | "txt") => {
        const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
        if (kind === "txt") return downloadText(`xray-knife-links-${stamp}.txt`, shown.map((r) => r.link));
        if (kind === "json") return downloadJSON(`xray-knife-results-${stamp}.json`, shown);
        downloadCSV(
            `xray-knife-results-${stamp}.csv`,
            ["status", "failure_kind", "delay_ms", "download_mbps", "upload_mbps", "http_code", "ttfb_ms", "connect_ms", "exit_ip", "country", "colo", "protocol", "name", "reason", "passed_endpoints", "total_endpoints", "link"],
            shown.map((r) => [r.status, r.failureKind ?? "", hasDelay(r) ? r.delay : null, r.download || null, r.upload || null, r.code || null, r.ttfb || null, r.connectTime || null,
                cleanIp(r.ip), cleanLocation(r.location), r.colo ?? "", resultProtocol(r), resultName(r), r.reason, r.successCount ?? null, r.totalCount ?? null, r.link]),
        );
    };

    const failed = results.filter((r) => !isWorking(r));
    const filterChip = (id: StatusFilter, label: string, n: number, tone: string) => (
        <button
            type="button"
            onClick={() => setStatusFilter(statusFilter === id ? "all" : id)}
            aria-pressed={statusFilter === id}
            className={cn("num inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors hover:bg-accent focus-visible:outline-2", statusFilter === id ? "border-primary/50 bg-primary/10" : "border-transparent")}
        >
            <span aria-hidden className={cn("size-2 rounded-full", tone)} />
            {label} <span className="font-semibold">{formatCount(n)}</span>
        </button>
    );

    return (
        <Panel
            title={t("Results")}
            description={results.length === 0 ? t("Results appear here as each config finishes.") : t("{shown} of {total} shown", { shown: formatCount(shown.length), total: formatCount(results.length) })}
            actions={
                <>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" size="sm" disabled={results.length === 0}><ClipboardList aria-hidden />{t("Copy")}<ChevronDown aria-hidden className="opacity-60" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem onSelect={() => copyLinks(results.filter((r) => r.status === "passed"), t("passed links"))}>{t("Passed links ({n})", { n: counts.passed })}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => copyLinks(results.filter(isWorking), t("working links"))}>{t("Passed and semi-passed ({n})", { n: counts.passed + counts.semi })}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => copyLinks(shown, t("links"))}>{t("Links shown ({n})", { n: shown.length })}</DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" size="sm" disabled={shown.length === 0}><Download aria-hidden />{t("Export")}<ChevronDown aria-hidden className="opacity-60" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuLabel>{t("Rows shown ({n})", { n: shown.length })}</DropdownMenuLabel>
                            <DropdownMenuItem onSelect={() => exportAs("csv")}>{t("CSV for spreadsheets")}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => exportAs("json")}>{t("JSON with all fields")}</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => exportAs("txt")}>{t("Links only (.txt)")}</DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-sm" aria-label={t("More actions")} disabled={results.length === 0}><ChevronDown aria-hidden /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem disabled={busy || failed.length === 0} onSelect={() => onRetest(failed.map((r) => r.link))}>
                                <RotateCw aria-hidden />{t("Test failed ones again ({n})", { n: failed.length })}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem disabled={busy} onSelect={() => setConfirmClear(true)}>
                                <Trash2 aria-hidden />{t("Clear results")}
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </>
            }
            bodyClassName="p-0"
            className="@container"
        >
            <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
                <div className="flex flex-wrap gap-1">
                    {filterChip("passed", t("Passed"), counts.passed, "bg-pass")}
                    {filterChip("semi-passed", t("Semi"), counts.semi, "bg-semi")}
                    {filterChip("failed", t("Failed"), counts.failed, "bg-fail")}
                </div>
                <div className="ms-auto flex min-w-0 basis-full items-center gap-2 @xl:basis-auto @xl:flex-none">
                    {protocols.length > 1 && (
                        <Select value={protocol} onValueChange={setProtocol}>
                            <SelectTrigger size="sm" className="w-auto min-w-28 shrink-0 text-xs" aria-label={t("Protocol")}><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">{t("All protocols")}</SelectItem>
                                {protocols.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                            </SelectContent>
                        </Select>
                    )}
                    <div className="relative min-w-0 flex-1 @xl:w-56 @xl:flex-none">
                        <Search className="pointer-events-none absolute start-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                        <Input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Search")} aria-label={t("Search results")} className="h-8 ps-7 text-xs" />
                    </div>
                </div>
            </div>

            {kinds.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 border-b px-3 py-2 text-xs">
                    <span className="me-1 text-muted-foreground">{t("Why configs failed")}:</span>
                    {kinds.map(([k, n]) => (
                        <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(kind === k ? null : k)} title={t(FAILURE_KINDS[k]?.hint ?? "")}
                            className={cn("num rounded-md border px-2 py-0.5 transition-colors hover:bg-accent focus-visible:outline-2", kind === k ? "border-fail/50 bg-fail/10 text-fail" : "border-border")}>
                            {t(failureLabel(k))} <span className="font-semibold">{n}</span>
                        </button>
                    ))}
                    {kind && <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => setKind(null)}>{t("Show all")}</Button>}
                </div>
            )}
            <div ref={scrollRef} className="max-h-[calc(100dvh-20rem)] min-h-72 overflow-auto">
                <table className="w-full table-fixed border-collapse text-sm">
                    <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0_var(--border)]">
                        <tr>
                            <SortHeader field="status" active={sort.field} dir={sort.dir} onSort={onSort} className="w-11 @lg:w-[7.5rem]"><span className="@max-lg:sr-only">{t("Status")}</span></SortHeader>
                            <SortHeader field="delay" active={sort.field} dir={sort.dir} onSort={onSort} className="w-[5.5rem] @lg:w-[7rem]">{t("Delay")}</SortHeader>
                            <SortHeader field="download" active={sort.field} dir={sort.dir} onSort={onSort} className="hidden w-[8.5rem] @3xl:table-cell">{t("Speed")}</SortHeader>
                            <SortHeader field="location" active={sort.field} dir={sort.dir} onSort={onSort} className="hidden w-[9rem] @xl:table-cell">{t("Exit")}</SortHeader>
                            <SortHeader field="protocol" active={sort.field} dir={sort.dir} onSort={onSort} className="hidden w-[6.5rem] @4xl:table-cell">{t("Protocol")}</SortHeader>
                            <SortHeader field="name" active={sort.field} dir={sort.dir} onSort={onSort}>{t("Config")}</SortHeader>
                            <th scope="col" className="w-[4.5rem] px-2 text-end text-xs font-medium text-muted-foreground @lg:w-[7rem]"><span className="sr-only">{t("Actions")}</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        {shown.length === 0 ? (
                            <tr>
                                <td colSpan={7}>
                                    {results.length === 0
                                        ? <EmptyState icon={Globe} title={busy ? t("Testing… the first results are on their way") : t("No results yet")}>{!busy && t("Paste share links on the left and run a test.")}</EmptyState>
                                        : <EmptyState icon={SearchX} title={t("No results match these filters")} />}
                                </td>
                            </tr>
                        ) : (
                            <>
                                {padTop > 0 && <tr aria-hidden><td colSpan={7} style={{ height: padTop, padding: 0 }} /></tr>}
                                {items.map((row) => {
                                    const r = shown[row.index];
                                    const loc = cleanLocation(r.location);
                                    const ip = cleanIp(r.ip);
                                    const frac = hasDelay(r) ? Math.min(r.delay / Math.max(maxDelay, 1), 1) : 0;
                                    const traceColor = r.status === "passed" ? "var(--pass)" : r.status === "semi-passed" ? "var(--semi)" : "var(--fail)";
                                    return (
                                        <tr key={r.link} className="h-[52px] border-b border-border/60 hover:bg-accent/40">
                                            <td className="px-2"><ResultStatusBadge status={r.status} compact /></td>
                                            <td className="px-2">
                                                <div className="num text-[13px] font-medium">{hasDelay(r) ? formatMs(r.delay) : "—"}</div>
                                                <div className="trace mt-1 w-full max-w-24" style={{ "--w": frac, "--trace-color": traceColor } as React.CSSProperties} aria-hidden />
                                            </td>
                                            <td className="num hidden px-2 text-xs @3xl:table-cell">
                                                {r.download > 0 || r.upload > 0 ? <><div>↓ {formatMbps(r.download)}</div><div className="text-muted-foreground">↑ {formatMbps(r.upload)}</div></> : <span className="text-muted-foreground">—</span>}
                                            </td>
                                            <td className="hidden px-2 text-xs @xl:table-cell">
                                                {loc || ip ? <><div>{loc ? `${flag(loc)} ${loc}` : ""}{r.colo && <span className="ms-1.5 text-muted-foreground">{r.colo}</span>}{r.warp && r.warp !== "off" && <span className="ms-1.5 text-info">WARP</span>}</div><div className="truncate font-mono text-[11px] text-muted-foreground" dir="ltr">{ip}</div></> : <span className="text-muted-foreground">—</span>}
                                            </td>
                                            <td className="hidden px-2 text-xs @4xl:table-cell">{resultProtocol(r)}</td>
                                            <td className="min-w-0 px-2">
                                                <button type="button" className="block w-full min-w-0 rounded text-start focus-visible:outline-2" onClick={() => setDetail(r)}>
                                                    <span className="block truncate text-[13px]" dir="auto">{resultName(r) || <span className="text-muted-foreground">{t("Unnamed")}</span>}</span>
                                                    <span dir="auto" className={cn("block truncate text-[11px]", isWorking(r) ? "text-muted-foreground" : "text-fail/90")}>
                                                        {isWorking(r)
                                                            ? (r.totalCount && r.totalCount > 1 ? t("{ok}/{total} endpoints", { ok: r.successCount ?? 0, total: r.totalCount }) : r.link.slice(0, 80))
                                                            : <>{r.failureKind && <span className="me-1.5 font-medium">{t(failureLabel(r.failureKind))}</span>}{r.reason || r.status}</>}
                                                    </span>
                                                </button>
                                            </td>
                                            <td className="px-1">
                                                <div className="flex justify-end">
                                                    <CopyButton text={r.link} label={t("Copy link")} done={t("Link copied")} />
                                                    <Button variant="ghost" size="icon-sm" onClick={() => setQrLink(r.link)} aria-label={t("Show QR code")} title={t("QR code")} className="hidden @lg:inline-flex"><QrCode aria-hidden /></Button>
                                                    <Button variant="ghost" size="icon-sm" onClick={() => setDetail(r)} aria-label={t("Details")} title={t("Details")}><Info aria-hidden /></Button>
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                                {padBottom > 0 && <tr aria-hidden><td colSpan={7} style={{ height: padBottom, padding: 0 }} /></tr>}
                            </>
                        )}
                    </tbody>
                </table>
            </div>
            <ResultDetails result={detail} onClose={() => setDetail(null)} canRetest={!busy} onRetest={(link) => { setDetail(null); onRetest([link]); }} />
            <ConfirmDialog open={confirmClear} onOpenChange={setConfirmClear} title={t("Clear results?")}
                description={t("This removes the results of the last web test run from the server. Runs saved to the database stay in History.")}
                confirmLabel={t("Clear")} onConfirm={onClear} />
            <QrDialog open={qrLink !== null} onOpenChange={(o) => !o && setQrLink(null)} text={qrLink ?? ""} />
        </Panel>
    );
}
