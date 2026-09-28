import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { History as HistoryIcon, Loader2, Trash2, ChevronLeft, ChevronRight, ArrowLeft, RotateCw, ClipboardList, Search, Radar, Download } from "lucide-react";
import { ExportDialog } from "@/components/common/ExportDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Panel } from "@/components/common/Panel";
import { EmptyState } from "@/components/common/EmptyState";
import { ResultStatusBadge } from "@/components/common/StatusBadge";
import { CopyButton } from "@/components/common/CopyButton";
import { ConfirmDialog } from "@/components/common/ConfirmButton";
import { api, isMissingEndpoint, type HttpRun, type HttpRunResult, type Paginated, type CfHistoryRow } from "@/services/api";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import type { Page } from "@/hooks/useHashRoute";
import { copyText, errorMessage, formatCount, formatMbps, formatMs, formatRelative } from "@/lib/utils";
import { linkRemark } from "@/lib/links";
import { toastStartError } from "@/lib/runControl";
import { useT } from "@/i18n";

function Pager({ page, total, perPage, onPage }: { page: number; total: number; perPage: number; onPage: (p: number) => void }) {
    const t = useT();
    const pages = Math.max(1, Math.ceil(total / perPage));
    if (pages <= 1) return null;
    return (
        <div className="flex items-center justify-end gap-2 border-t px-3 py-2 text-xs">
            <Button size="icon-sm" variant="outline" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label={t("Previous page")}><ChevronLeft className="rtl:-scale-x-100" aria-hidden /></Button>
            <span className="num">{t("Page {p} of {n}", { p: page, n: pages })}</span>
            <Button size="icon-sm" variant="outline" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label={t("Next page")}><ChevronRight className="rtl:-scale-x-100" aria-hidden /></Button>
        </div>
    );
}

async function startTest(links: string[], navigate: (p: Page) => void, t: ReturnType<typeof useT>) {
    if (links.length === 0) { toast.info(t("Nothing to test")); return; }
    const rt = useRuntimeStore.getState();
    if (rt.httpStatus !== "idle") { toast.error(t("An HTTP test is already running")); return; }
    rt.clearHttpResults();
    rt.setHttpStatus("starting");
    try {
        await api.startHttpTest(useSettingsStore.getState().httpSettings, { links });
        if (useRuntimeStore.getState().httpStatus === "starting") useRuntimeStore.getState().setHttpStatus("running");
        navigate("http");
    } catch (err) {
        useRuntimeStore.getState().setHttpStatus("idle", errorMessage(err));
        toastStartError(err, t("HTTP test"));
    }
}

function RunResults({ run, onBack, navigate }: { run: HttpRun; onBack: () => void; navigate: (p: Page) => void }) {
    const t = useT();
    const [status, setStatus] = useState("passed,semi-passed");
    const [query, setQuery] = useState("");
    const q = useDebouncedValue(query.trim(), 300);
    const [sort, setSort] = useState("delay");
    const [page, setPage] = useState(1);
    const [data, setData] = useState<Paginated<HttpRunResult> | null>(null);
    const [error, setError] = useState<string | null>(null);
    const perPage = 100;

    useEffect(() => { setPage(1); }, [status, q, sort]);
    useEffect(() => {
        let live = true;
        api.httpRunResults(run.id, { status: status === "all" ? undefined : status, q: q || undefined, sort, page, per_page: perPage })
            .then((d) => { if (live) { setData(d); setError(null); } })
            .catch((err) => { if (live) setError(errorMessage(err)); });
        return () => { live = false; };
    }, [run.id, status, q, sort, page]);

    const collect = async (statuses: string) => {
        const out: string[] = [];
        for (let p = 1; p <= 50; p++) {
            const d = await api.httpRunResults(run.id, { status: statuses, page: p, per_page: 1000 });
            out.push(...d.items.map((r) => r.link));
            if (out.length >= d.total || d.items.length === 0) break;
        }
        return out;
    };

    return (
        <Panel
            title={<span className="inline-flex items-center gap-2"><Button size="icon-sm" variant="ghost" onClick={onBack} aria-label={t("Back to runs")}><ArrowLeft className="rtl:-scale-x-100" aria-hidden /></Button>{t("Run #{id}", { id: run.id })}</span>}
            description={`${new Date(run.startTime).toLocaleString()}, ${t("{n} configs", { n: formatCount(run.configCount) })}`}
            actions={
                <>
                    <Button size="sm" variant="outline" onClick={async () => {
                        try { const l = await collect("passed,semi-passed"); await copyText(l.join("\n")); toast.success(t("Copied {n} working links", { n: l.length })); }
                        catch (err) { toast.error(t("Could not copy"), { description: errorMessage(err) }); }
                    }}><ClipboardList aria-hidden />{t("Copy working")}</Button>
                    <Button size="sm" variant="outline" onClick={async () => {
                        try { await startTest(await collect("failed,broken,timeout"), navigate, t); }
                        catch (err) { toast.error(t("Could not load the failed configs"), { description: errorMessage(err) }); }
                    }}><RotateCw aria-hidden />{t("Test failed again")}</Button>
                </>
            }
            bodyClassName="p-0"
        >
            <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
                <Select value={status} onValueChange={setStatus}>
                    <SelectTrigger size="sm" className="w-auto min-w-40 text-xs" aria-label={t("Status")}><SelectValue /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="passed,semi-passed">{t("Working")}</SelectItem>
                        <SelectItem value="passed">{t("Passed")}</SelectItem>
                        <SelectItem value="failed,broken,timeout">{t("Failed")}</SelectItem>
                        <SelectItem value="all">{t("All")}</SelectItem>
                    </SelectContent>
                </Select>
                <Select value={sort} onValueChange={setSort}>
                    <SelectTrigger size="sm" className="w-auto min-w-36 text-xs" aria-label={t("Sort")}><SelectValue /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="delay">{t("Fastest first")}</SelectItem>
                        <SelectItem value="-download">{t("Best download first")}</SelectItem>
                        <SelectItem value="status">{t("By status")}</SelectItem>
                    </SelectContent>
                </Select>
                <div className="relative ms-auto w-full sm:w-56">
                    <Search className="pointer-events-none absolute start-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                    <Input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Search")} aria-label={t("Search results")} className="h-8 ps-7 text-xs" />
                </div>
            </div>
            {error ? <p role="alert" className="p-4 text-sm text-fail">{error}</p> : !data ? (
                <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Loading…")}</p>
            ) : data.items.length === 0 ? <EmptyState icon={HistoryIcon} title={t("No results match")} /> : (
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead className="bg-muted/40 text-xs text-muted-foreground">
                            <tr>
                                <th scope="col" className="px-3 py-2 text-start font-medium">{t("Status")}</th>
                                <th scope="col" className="px-3 py-2 text-start font-medium">{t("Delay")}</th>
                                <th scope="col" className="hidden px-3 py-2 text-start font-medium sm:table-cell">{t("Download")}</th>
                                <th scope="col" className="hidden px-3 py-2 text-start font-medium md:table-cell">{t("Exit")}</th>
                                <th scope="col" className="px-3 py-2 text-start font-medium">{t("Config")}</th>
                                <th scope="col"><span className="sr-only">{t("Actions")}</span></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y">
                            {data.items.map((r) => (
                                <tr key={r.id}>
                                    <td className="px-3 py-2"><ResultStatusBadge status={r.status} compact /></td>
                                    <td className="num px-3 py-2">{r.delay > 0 ? formatMs(r.delay) : "—"}</td>
                                    <td className="num hidden px-3 py-2 sm:table-cell">{formatMbps(r.download)}</td>
                                    <td className="hidden px-3 py-2 text-xs md:table-cell">{r.location && r.location !== "null" ? r.location : ""} <span className="font-mono text-muted-foreground">{r.ip}</span></td>
                                    <td className="max-w-0 px-3 py-2"><span className="block truncate">{linkRemark(r.link) || r.link.slice(0, 60)}</span>{r.reason && r.status !== "passed" && <span className="block truncate text-xs text-fail/90">{r.reason}</span>}</td>
                                    <td className="px-2"><CopyButton text={r.link} label={t("Copy link")} done={t("Link copied")} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
            {data && <Pager page={page} total={data.total} perPage={perPage} onPage={setPage} />}
        </Panel>
    );
}

function HttpRuns({ navigate }: { navigate: (p: Page) => void }) {
    const t = useT();
    const [page, setPage] = useState(1);
    const [data, setData] = useState<Paginated<HttpRun> | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [open, setOpen] = useState<HttpRun | null>(null);
    const [del, setDel] = useState<HttpRun | null>(null);
    const [exporting, setExporting] = useState(false);
    const perPage = 25;

    const load = useCallback(() => {
        api.httpRuns(page, perPage).then((d) => { setData(d); setError(null); }).catch((err) => setError(isMissingEndpoint(err) ? t("This server has no history API.") : errorMessage(err)));
    }, [page, t]);
    useEffect(() => { load(); }, [load]);

    if (open) return <RunResults run={open} onBack={() => setOpen(null)} navigate={navigate} />;
    return (
        <Panel title={t("HTTP test runs")} description={t("Runs started with \"Save results to the database\", from the panel or the CLI.")} bodyClassName="p-0"
            actions={<Button size="sm" variant="outline" onClick={() => setExporting(true)}><Download aria-hidden />{t("Export working configs")}</Button>}>
            <ExportDialog open={exporting} onOpenChange={setExporting} target="all" title={t("Export tested configs")} />
            {error ? <p role="alert" className="p-4 text-sm text-fail">{error}</p> : !data ? (
                <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Loading…")}</p>
            ) : data.items.length === 0 ? (
                <EmptyState icon={HistoryIcon} title={t("No saved runs yet")}>{t("Turn on \"Save results to the database\" in the HTTP tester, or run `xray-knife http --save-db`.")}</EmptyState>
            ) : (
                <ul className="divide-y">
                    {data.items.map((run) => {
                        const c = run.counts;
                        return (
                            <li key={run.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                                <button type="button" onClick={() => setOpen(run)} className="min-w-0 flex-1 rounded text-start focus-visible:outline-2">
                                    <p className="text-sm font-medium">{t("Run #{id}", { id: run.id })} <span className="font-normal text-muted-foreground">{formatRelative(run.startTime)}</span></p>
                                    <p className="num text-xs text-muted-foreground">
                                        {t("{n} configs", { n: formatCount(run.configCount) })}
                                        {run.endTime && `, ${t("took {t}", { t: formatMs(new Date(run.endTime).getTime() - new Date(run.startTime).getTime()) })}`}
                                    </p>
                                </button>
                                {c && (
                                    <div className="num flex gap-3 text-xs">
                                        <span className="text-pass">{t("{n} passed", { n: formatCount(c.passed) })}</span>
                                        {c.semiPassed > 0 && <span className="text-semi">{t("{n} semi", { n: formatCount(c.semiPassed) })}</span>}
                                        <span className="text-muted-foreground">{t("{n} failed", { n: formatCount(c.failed + c.broken) })}</span>
                                    </div>
                                )}
                                <div className="flex gap-1">
                                    <Button size="sm" variant="outline" onClick={() => setOpen(run)}>{t("Open")}</Button>
                                    <Button size="icon-sm" variant="ghost" onClick={() => setDel(run)} aria-label={t("Delete run {id}", { id: run.id })}><Trash2 aria-hidden /></Button>
                                </div>
                            </li>
                        );
                    })}
                </ul>
            )}
            {data && <Pager page={page} total={data.total} perPage={perPage} onPage={setPage} />}
            <ConfirmDialog open={del !== null} onOpenChange={(o) => !o && setDel(null)} title={t("Delete this run?")} description={t("Its saved results are deleted from the database.")}
                confirmLabel={t("Delete")} onConfirm={async () => {
                    if (!del) return;
                    try { await api.deleteHttpRun(del.id); toast.success(t("Run deleted")); load(); }
                    catch (err) { toast.error(t("Could not delete"), { description: errorMessage(err) }); }
                }} />
        </Panel>
    );
}

function CfHistory() {
    const t = useT();
    const [page, setPage] = useState(1);
    const [okOnly, setOkOnly] = useState(true);
    const [data, setData] = useState<Paginated<CfHistoryRow> | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [confirm, setConfirm] = useState(false);
    const perPage = 100;

    const load = useCallback(() => {
        api.cfHistoryDB({ ok: okOnly, sort: "latency", page, per_page: perPage }).then((d) => { setData(d); setError(null); }).catch((err) => setError(errorMessage(err)));
    }, [okOnly, page]);
    useEffect(() => { load(); }, [load]);
    useEffect(() => { setPage(1); }, [okOnly]);

    return (
        <Panel title={t("Saved Cloudflare scan results")} description={data ? t("{n} IPs", { n: formatCount(data.total) }) : undefined}
            actions={<Button size="sm" variant="ghost" onClick={() => setConfirm(true)} disabled={!data?.total}><Trash2 aria-hidden />{t("Clear")}</Button>} bodyClassName="p-0">
            <div className="flex items-center gap-2 border-b px-3 py-2">
                <Checkbox id="cfh-ok" checked={okOnly} onCheckedChange={(c) => setOkOnly(Boolean(c))} />
                <Label htmlFor="cfh-ok" className="cursor-pointer text-xs font-normal">{t("Only IPs that answered")}</Label>
            </div>
            {error ? <p role="alert" className="p-4 text-sm text-fail">{error}</p> : !data ? (
                <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Loading…")}</p>
            ) : data.items.length === 0 ? <EmptyState icon={Radar} title={t("No saved scan results")}>{t("Turn on \"Save results to the database\" in the scanner's advanced options.")}</EmptyState> : (
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead className="bg-muted/40 text-xs text-muted-foreground">
                            <tr>
                                <th scope="col" className="px-3 py-2 text-start font-medium">{t("IP")}</th>
                                <th scope="col" className="px-3 py-2 text-start font-medium">{t("Latency")}</th>
                                <th scope="col" className="hidden px-3 py-2 text-start font-medium sm:table-cell">{t("Download")}</th>
                                <th scope="col" className="hidden px-3 py-2 text-start font-medium sm:table-cell">{t("Scanned")}</th>
                                <th scope="col"><span className="sr-only">{t("Actions")}</span></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y">
                            {data.items.map((r) => (
                                <tr key={r.ip}>
                                    <td className="px-3 py-2 font-mono text-xs" dir="ltr">{r.ip}</td>
                                    <td className="num px-3 py-2">{r.error ? <span className="text-xs text-fail">{r.error}</span> : formatMs(r.latency)}</td>
                                    <td className="num hidden px-3 py-2 sm:table-cell">{formatMbps(r.download)}</td>
                                    <td className="hidden px-3 py-2 text-xs text-muted-foreground sm:table-cell">{formatRelative(r.lastScannedAt)}</td>
                                    <td className="px-2"><CopyButton text={r.ip} label={t("Copy IP")} done={t("IP copied")} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
            {data && <Pager page={page} total={data.total} perPage={perPage} onPage={setPage} />}
            <ConfirmDialog open={confirm} onOpenChange={setConfirm} title={t("Clear saved scan results?")} description={t("Deletes every saved Cloudflare scan result from the database.")}
                confirmLabel={t("Clear")} onConfirm={async () => {
                    try { await api.clearCfHistoryDB(); toast.success(t("Saved scan results cleared")); load(); }
                    catch (err) { toast.error(t("Could not clear"), { description: errorMessage(err) }); }
                }} />
        </Panel>
    );
}

export default function HistoryPage({ navigate }: { navigate: (p: Page) => void }) {
    const t = useT();
    return (
        <Tabs defaultValue="http" className="space-y-3">
            <TabsList>
                <TabsTrigger value="http">{t("HTTP tests")}</TabsTrigger>
                <TabsTrigger value="cf">{t("Cloudflare scans")}</TabsTrigger>
            </TabsList>
            <TabsContent value="http"><HttpRuns navigate={navigate} /></TabsContent>
            <TabsContent value="cf"><CfHistory /></TabsContent>
        </Tabs>
    );
}
