import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Plus, RefreshCw, Loader2, FlaskConical, ListTree, Pencil, Trash2, Rss, Server, ChevronDown, AlertTriangle, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Panel } from "@/components/common/Panel";
import { Field } from "@/components/common/Field";
import { Collapsible } from "@/components/common/Collapsible";
import { EmptyState } from "@/components/common/EmptyState";
import { ConfirmDialog } from "@/components/common/ConfirmButton";
import { ConfigsDialog } from "./ConfigsDialog";
import { ShareLinks } from "./ShareLinks";
import { ExportDialog } from "@/components/common/ExportDialog";
import { api, isMissingEndpoint, type FetchOptions, type FetchResult, type Subscription } from "@/services/api";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { usePersistentState } from "@/hooks/usePersistentState";
import type { Page } from "@/hooks/useHashRoute";
import { errorMessage, formatCount, formatRelative } from "@/lib/utils";
import { toastStartError } from "@/lib/runControl";
import { useT } from "@/i18n";

interface EditState {
    id: number | null;
    url: string;
    remark: string;
    userAgent: string;
}

export default function SubscriptionsPage({ navigate }: { navigate: (p: Page) => void }) {
    const t = useT();
    const [subs, setSubs] = useState<Subscription[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [missing, setMissing] = useState(false);
    const [busyIds, setBusyIds] = useState<Set<number | "all">>(new Set());
    const [edit, setEdit] = useState<EditState | null>(null);
    const [saving, setSaving] = useState(false);
    const [remove, setRemove] = useState<Subscription | null>(null);
    const [configsOf, setConfigsOf] = useState<Subscription | null>(null);
    const [exportOf, setExportOf] = useState<Subscription | "all" | null>(null);
    const [fetchOpts, setFetchOpts] = usePersistentState<Required<Pick<FetchOptions, "maxBytes" | "maxLinks" | "timeoutSec">> & { proxy: string }>(
        "subs-fetch-options", { maxBytes: 0, maxLinks: 0, timeoutSec: 0, proxy: "" });
    const httpBusy = useRuntimeStore((s) => s.httpStatus !== "idle");

    // "clash document, 3 lines unreadable; skipped: unsupported type (2)"
    const fetchDetails = (r: FetchResult): string => {
        const bits: string[] = [];
        if (r.format && r.format !== "plain" && r.format !== "base64") bits.push(t("{format} document", { format: r.format }));
        if (r.unparsable > 0) bits.push(t("{n} lines could not be read", { n: r.unparsable }));
        if (r.skipSummary?.length) bits.push(t("skipped: {list}", { list: r.skipSummary.join(", ") }));
        return bits.join("; ");
    };

    const load = useCallback(async () => {
        try {
            setSubs(await api.subscriptions());
            setError(null);
        } catch (err) {
            if (isMissingEndpoint(err)) setMissing(true);
            else setError(errorMessage(err));
        }
    }, []);

    useEffect(() => { void load(); }, [load]);

    const mark = (id: number | "all", on: boolean) => setBusyIds((s) => {
        const n = new Set(s);
        if (on) n.add(id); else n.delete(id);
        return n;
    });

    const opts = (): FetchOptions => ({
        ...(fetchOpts.maxBytes > 0 ? { maxBytes: fetchOpts.maxBytes * 1024 * 1024 } : {}),
        ...(fetchOpts.maxLinks > 0 ? { maxLinks: fetchOpts.maxLinks } : {}),
        ...(fetchOpts.timeoutSec > 0 ? { timeoutSec: fetchOpts.timeoutSec } : {}),
        ...(fetchOpts.proxy.trim() ? { proxy: fetchOpts.proxy.trim() } : {}),
    });

    const fetchOne = async (s: Subscription) => {
        mark(s.id, true);
        try {
            const r = await api.fetchSubscription(s.id, opts());
            toast.success(r.notModified ? t("{name}: not changed since the last fetch", { name: s.remark || s.url }) : t("{name}: {saved} configs saved", { name: s.remark || s.url, saved: formatCount(r.saved) }), {
                description: fetchDetails(r) || undefined,
            });
            await load();
        } catch (err) {
            toast.error(t("Fetch failed"), { description: errorMessage(err) });
        } finally {
            mark(s.id, false);
        }
    };

    const fetchAll = async () => {
        mark("all", true);
        try {
            const r = await api.fetchAllSubscriptions(opts());
            const failed = r.results.filter((x) => x.error);
            const saved = r.results.reduce((n, x) => n + (x.saved || 0), 0);
            const details = r.results.filter((x) => !x.error).map(fetchDetails).filter(Boolean).slice(0, 3).join("\n");
            if (failed.length) toast.warning(t("{n} subscriptions failed to fetch", { n: failed.length }), { description: failed.map((f) => f.error).slice(0, 3).join("\n") });
            else toast.success(t("All subscriptions fetched: {n} configs saved", { n: formatCount(saved) }), { description: details || undefined });
            await load();
        } catch (err) {
            toast.error(t("Fetch failed"), { description: errorMessage(err) });
        } finally {
            mark("all", false);
        }
    };

    const save = async () => {
        if (!edit) return;
        const url = edit.url.trim();
        if (!/^https?:\/\/[^\s/]+/i.test(url)) { toast.error(t("Enter an http:// or https:// address")); return; }
        setSaving(true);
        try {
            if (edit.id === null) {
                const created = await api.addSubscription({ url, remark: edit.remark.trim(), userAgent: edit.userAgent.trim() });
                toast.success(t("Subscription added"), { description: t("Fetching it now…") });
                setEdit(null);
                await load();
                void fetchOne(created);
            } else {
                await api.updateSubscription(edit.id, { url, remark: edit.remark.trim(), userAgent: edit.userAgent.trim() });
                toast.success(t("Subscription updated"));
                setEdit(null);
                await load();
            }
        } catch (err) {
            toast.error(t("Could not save"), { description: errorMessage(err) });
        } finally {
            setSaving(false);
        }
    };

    const toggle = async (s: Subscription, enabled: boolean) => {
        setSubs((list) => list?.map((x) => (x.id === s.id ? { ...x, enabled } : x)) ?? null);
        try {
            await api.updateSubscription(s.id, { enabled });
        } catch (err) {
            toast.error(t("Could not update"), { description: errorMessage(err) });
            void load();
        }
    };

    const del = async (s: Subscription) => {
        try {
            await api.deleteSubscription(s.id);
            toast.success(t("Subscription removed"));
            await load();
        } catch (err) {
            toast.error(t("Could not remove"), { description: errorMessage(err) });
        }
    };

    const test = async (s: Subscription) => {
        const settings = useSettingsStore.getState().httpSettings;
        const rt = useRuntimeStore.getState();
        rt.clearHttpResults();
        rt.setHttpStatus("starting");
        try {
            await api.testSubscription(s.id, settings);
            if (useRuntimeStore.getState().httpStatus === "starting") useRuntimeStore.getState().setHttpStatus("running");
            navigate("http");
        } catch (err) {
            useRuntimeStore.getState().setHttpStatus("idle", errorMessage(err));
            toastStartError(err, t("HTTP test"));
        }
    };

    const useAsPool = () => {
        try { localStorage.setItem("proxy-source", JSON.stringify("db")); } catch { /* ignore */ }
        navigate("proxy");
    };

    if (missing) {
        return (
            <Panel title={t("Subscriptions")}>
                <EmptyState icon={Rss} title={t("This server has no subscription API")}>{t("Update xray-knife, or manage subscriptions with `xray-knife subs` on the command line.")}</EmptyState>
            </Panel>
        );
    }

    const total = subs?.reduce((n, s) => n + (s.enabled ? s.configCount : 0), 0) ?? 0;
    return (
        <div className="space-y-4">
            <Panel
                title={t("Subscriptions")}
                description={subs ? (subs.length === 1 ? t("1 subscription, {c} configs in enabled ones", { c: formatCount(total) }) : t("{n} subscriptions, {c} configs in enabled ones", { n: subs.length, c: formatCount(total) })) : undefined}
                actions={
                    <>
                        <Button size="sm" onClick={() => setEdit({ id: null, url: "", remark: "", userAgent: "" })}><Plus aria-hidden />{t("Add")}</Button>
                        <Button size="sm" variant="outline" onClick={fetchAll} disabled={!subs?.length || busyIds.has("all")}>
                            {busyIds.has("all") ? <Loader2 className="animate-spin" aria-hidden /> : <RefreshCw aria-hidden />}{t("Fetch all")}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setExportOf("all")} disabled={!total}><Download aria-hidden />{t("Export")}</Button>
                        <Button size="sm" variant="outline" onClick={useAsPool} disabled={!total}><Server aria-hidden />{t("Use as proxy pool")}</Button>
                    </>
                }
                bodyClassName="p-0"
            >
                {error && (
                    <p role="alert" className="flex items-center gap-2 border-b px-4 py-2 text-sm text-fail"><AlertTriangle className="size-4" aria-hidden />{error}
                        <Button size="sm" variant="ghost" className="ms-auto" onClick={load}>{t("Retry")}</Button></p>
                )}
                {subs === null && !error ? (
                    <p className="flex items-center gap-2 p-6 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Loading…")}</p>
                ) : subs && subs.length === 0 ? (
                    <EmptyState icon={Rss} title={t("No subscriptions yet")}>{t("Add the subscription URL your provider or channel gives you. xray-knife fetches it, removes duplicates and keeps the configs ready for testing.")}</EmptyState>
                ) : (
                    <ul className="divide-y">
                        {subs?.map((s) => {
                            const busy = busyIds.has(s.id) || busyIds.has("all");
                            return (
                                <li key={s.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                                    <Checkbox id={`sub-on-${s.id}`} checked={s.enabled} onCheckedChange={(c) => toggle(s, Boolean(c))} aria-label={t("Enabled")} />
                                    <div className="min-w-0 flex-1">
                                        <p className="truncate text-sm font-medium">{s.remark || s.url.replace(/^https?:\/\//, "")}</p>
                                        <p className="truncate font-mono text-[11px] text-muted-foreground" dir="ltr">{s.url}</p>
                                    </div>
                                    <div className="num text-end text-xs text-muted-foreground">
                                        <div className="text-sm font-medium text-foreground">{formatCount(s.configCount)} {t("configs")}</div>
                                        <div>{s.lastFetchedAt ? t("fetched {when}", { when: formatRelative(s.lastFetchedAt) }) : t("never fetched")}</div>
                                    </div>
                                    <div className="flex items-center gap-1">
                                        <Button size="sm" variant="outline" onClick={() => fetchOne(s)} disabled={busy} aria-label={t("Fetch {name}", { name: s.remark || s.url })}>
                                            {busy ? <Loader2 className="animate-spin" aria-hidden /> : <RefreshCw aria-hidden />}<span className="hidden sm:inline">{t("Fetch")}</span>
                                        </Button>
                                        <Button size="sm" variant="outline" onClick={() => test(s)} disabled={httpBusy || s.configCount === 0} title={httpBusy ? t("An HTTP test is already running") : undefined}>
                                            <FlaskConical aria-hidden /><span className="hidden sm:inline">{t("Test")}</span>
                                        </Button>
                                        <DropdownMenu>
                                            <DropdownMenuTrigger asChild><Button size="icon-sm" variant="ghost" aria-label={t("More actions")}><ChevronDown aria-hidden /></Button></DropdownMenuTrigger>
                                            <DropdownMenuContent align="end">
                                                <DropdownMenuItem onSelect={() => setConfigsOf(s)}><ListTree aria-hidden />{t("Browse configs")}</DropdownMenuItem>
                                                <DropdownMenuItem disabled={s.configCount === 0} onSelect={() => setExportOf(s)}><Download aria-hidden />{t("Export…")}</DropdownMenuItem>
                                                <DropdownMenuItem onSelect={() => setEdit({ id: s.id, url: s.url, remark: s.remark, userAgent: s.userAgent })}><Pencil aria-hidden />{t("Edit")}</DropdownMenuItem>
                                                <DropdownMenuSeparator />
                                                <DropdownMenuItem onSelect={() => setRemove(s)} className="text-fail focus:text-fail"><Trash2 aria-hidden />{t("Remove")}</DropdownMenuItem>
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                    </div>
                                </li>
                            );
                        })}
                    </ul>
                )}
            </Panel>

            {subs && <ShareLinks subs={subs} />}

            <Collapsible title={t("Fetch limits")} summary={fetchOpts.proxy ? t("through {proxy}", { proxy: fetchOpts.proxy }) : t("Server defaults")} className="bg-card">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                    <Field id="fo-bytes" label={t("Max size (MB)")} hint={t("0 = default")}><InputNumber id="fo-bytes" label={t("Max size")} min={0} max={1024} value={fetchOpts.maxBytes} onChange={(v) => setFetchOpts({ ...fetchOpts, maxBytes: v })} /></Field>
                    <Field id="fo-links" label={t("Max links")} hint={t("0 = default")}><InputNumber id="fo-links" label={t("Max links")} min={0} max={10_000_000} step={1000} value={fetchOpts.maxLinks} onChange={(v) => setFetchOpts({ ...fetchOpts, maxLinks: v })} /></Field>
                    <Field id="fo-timeout" label={t("Timeout (s)")} hint={t("0 = default")}><InputNumber id="fo-timeout" label={t("Fetch timeout")} min={0} max={3600} value={fetchOpts.timeoutSec} onChange={(v) => setFetchOpts({ ...fetchOpts, timeoutSec: v })} /></Field>
                </div>
                <Field id="fo-proxy" label={t("Fetch through a proxy (optional)")} hint={t("For subscription hosts that are blocked on this network, e.g. socks5://127.0.0.1:9999 while the local proxy runs.")}>
                    <Input id="fo-proxy" value={fetchOpts.proxy} onChange={(e) => setFetchOpts({ ...fetchOpts, proxy: e.target.value })} placeholder="socks5://127.0.0.1:9999" dir="ltr" className="font-mono text-xs md:text-xs" />
                </Field>
            </Collapsible>

            <Dialog open={edit !== null} onOpenChange={(o) => !o && setEdit(null)}>
                <DialogContent className="sm:max-w-lg">
                    <DialogHeader>
                        <DialogTitle>{edit?.id === null ? t("Add subscription") : t("Edit subscription")}</DialogTitle>
                        <DialogDescription>{t("A URL that returns share links, one per line or base64-encoded.")}</DialogDescription>
                    </DialogHeader>
                    {edit && (
                        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void save(); }}>
                            <Field id="sub-url" label={t("URL")}><Input id="sub-url" value={edit.url} onChange={(e) => setEdit({ ...edit, url: e.target.value })} placeholder="https://…" dir="ltr" autoFocus required inputMode="url" /></Field>
                            <Field id="sub-remark" label={t("Name (optional)")}><Input id="sub-remark" value={edit.remark} onChange={(e) => setEdit({ ...edit, remark: e.target.value })} /></Field>
                            <Field id="sub-ua" label={t("User agent (optional)")} hint={t("Some providers only answer known clients, e.g. v2rayNG/1.8.5")}><Input id="sub-ua" value={edit.userAgent} onChange={(e) => setEdit({ ...edit, userAgent: e.target.value })} dir="ltr" /></Field>
                            <DialogFooter>
                                <Button type="button" variant="secondary" onClick={() => setEdit(null)}>{t("Cancel")}</Button>
                                <Button type="submit" disabled={saving}>{saving && <Loader2 className="animate-spin" aria-hidden />}{edit.id === null ? t("Add and fetch") : t("Save")}</Button>
                            </DialogFooter>
                        </form>
                    )}
                </DialogContent>
            </Dialog>
            <ConfirmDialog open={remove !== null} onOpenChange={(o) => !o && setRemove(null)} title={t("Remove this subscription?")}
                description={t("Its configs are deleted from the database too. Test history stays.")} confirmLabel={t("Remove")} onConfirm={async () => { if (remove) await del(remove); }} />
            <ConfigsDialog subscription={configsOf} onClose={() => setConfigsOf(null)} />
            <ExportDialog open={exportOf !== null} onOpenChange={(o) => !o && setExportOf(null)}
                target={exportOf === "all" || exportOf === null ? "all" : [exportOf.id]}
                title={exportOf === "all" || exportOf === null ? t("Export all enabled subscriptions") : t("Export {name}", { name: exportOf.remark || exportOf.url })} />
        </div>
    );
}
