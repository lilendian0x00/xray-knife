import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Plus, Link2, Loader2, Pencil, Trash2, AlertTriangle, QrCode, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { InputNumber } from "@/components/ui/input-number";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Panel } from "@/components/common/Panel";
import { Field } from "@/components/common/Field";
import { EmptyState } from "@/components/common/EmptyState";
import { CopyButton } from "@/components/common/CopyButton";
import { QrDialog } from "@/components/common/QrDialog";
import { ConfirmDialog } from "@/components/common/ConfirmButton";
import { EXPORT_FORMATS } from "@/lib/exportFormats";
import { Rich } from "@/components/common/Rich";
import { api, isMissingEndpoint, type ExportFormat, type SubToken, type SubTokenDefaults, type Subscription } from "@/services/api";
import { useServerStore } from "@/stores/serverStore";
import { cn, errorMessage, formatRelative } from "@/lib/utils";
import { useT } from "@/i18n";

const DEFAULTS: Required<Omit<SubTokenDefaults, "subscriptionIds" | "protocol">> & Pick<SubTokenDefaults, "subscriptionIds" | "protocol"> = {
    format: "base64", status: "passed", max: 200, maxAgeHours: 0, updateIntervalHours: 6, subscriptionIds: [], protocol: "",
};

const LOOPBACK = /^(127\.|\[?::1\]?|localhost)/i;

/** Hostname of the address the panel listens on, e.g. "127.0.0.1" from "127.0.0.1:8080". */
function bindHost(listenAddr: string | undefined): string {
    if (!listenAddr) return "";
    const m = /^\[([^\]]+)\]|^([^:]+)/.exec(listenAddr);
    return (m?.[1] ?? m?.[2] ?? "").toLowerCase();
}

function describe(d: SubTokenDefaults, subs: Subscription[], t: ReturnType<typeof useT>): string {
    const fmt = EXPORT_FORMATS.find((f) => f.value === d.format)?.label ?? d.format ?? "base64";
    const names = d.subscriptionIds?.length ? d.subscriptionIds.map((id) => subs.find((s) => s.id === id)?.remark || `#${id}`).join(", ") : t("all enabled subscriptions");
    const status = d.status === "any" ? t("any status") : d.status === "semi-passed" ? t("passed + semi-passed") : t("passed only");
    return `${t(fmt)}, ${status}, ${t("max {n}", { n: d.max ?? 200 })}, ${names}`;
}

interface EditState { id: SubToken["id"] | null; name: string; d: SubTokenDefaults }

export function ShareLinks({ subs }: { subs: Subscription[] }) {
    const t = useT();
    const info = useServerStore((s) => s.info);
    const [tokens, setTokens] = useState<SubToken[] | null>(null);
    const [missing, setMissing] = useState(false);
    const [edit, setEdit] = useState<EditState | null>(null);
    const [saving, setSaving] = useState(false);
    const [created, setCreated] = useState<{ url: string; name: string; format: ExportFormat } | null>(null);
    const [qr, setQr] = useState<string | null>(null);
    const [revoke, setRevoke] = useState<SubToken | null>(null);

    const load = useCallback(() => {
        api.subTokens().then((l) => setTokens(l ?? [])).catch((err) => { if (isMissingEndpoint(err)) setMissing(true); else setTokens([]); });
    }, []);
    useEffect(() => { load(); }, [load]);

    if (missing) return null;

    const host = bindHost(info?.listenAddr);
    const loopbackOnly = (host !== "" && LOOPBACK.test(host)) || LOOPBACK.test(window.location.hostname);
    const plainHttp = info?.tls === false || window.location.protocol === "http:";

    const save = async () => {
        if (!edit) return;
        setSaving(true);
        try {
            if (edit.id === null) {
                const r = await api.createSubToken({ name: edit.name.trim() || undefined, ...edit.d });
                setCreated({ url: `${window.location.origin}${r.path}`, name: edit.name.trim() || t("Subscription link"), format: edit.d.format ?? "base64" });
            } else {
                await api.updateSubToken(edit.id, { name: edit.name.trim(), defaults: edit.d });
                toast.success(t("Link updated"));
            }
            setEdit(null);
            load();
        } catch (err) {
            toast.error(t("Could not save"), { description: errorMessage(err) });
        } finally {
            setSaving(false);
        }
    };

    const d = edit?.d ?? DEFAULTS;
    const setD = (patch: Partial<SubTokenDefaults>) => edit && setEdit({ ...edit, d: { ...edit.d, ...patch } });
    const withFormat = (url: string, f: ExportFormat) => `${url}?format=${f}`;

    return (
        <>
            <Panel
                title={t("Share with your phone")}
                description={t("Private subscription URLs that serve the configs that passed recently. Clients refresh them on their own; no login needed.")}
                actions={<Button size="sm" variant="outline" onClick={() => setEdit({ id: null, name: "", d: { ...DEFAULTS } })}><Plus aria-hidden />{t("New link")}</Button>}
                bodyClassName="p-0"
            >
                {(loopbackOnly || plainHttp) && (
                    <div className="space-y-1 border-b bg-semi/10 px-4 py-2 text-xs">
                        {loopbackOnly && (
                            <p className="flex items-start gap-2"><AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-semi" aria-hidden />
                                <span><Rich text={t("The panel only listens on this computer ({addr}), so a phone can't open these links. Start it with `xray-knife webui -a 0.0.0.0` (or --allow-host with your LAN name) and open the panel through that address.", { addr: info?.listenAddr ?? window.location.host })} /></span></p>
                        )}
                        {plainHttp && !loopbackOnly && (
                            <p className="flex items-start gap-2"><AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-semi" aria-hidden />
                                <span>{t("Served over plain HTTP: anyone on the network path can read the link and the configs. Use --tls-cert/--tls-key.")}</span></p>
                        )}
                    </div>
                )}
                {tokens === null ? (
                    <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Loading…")}</p>
                ) : tokens.length === 0 ? (
                    <EmptyState icon={Link2} title={t("No shared links yet")}>{t("Create one, scan it with v2rayNG, Hiddify or Clash, and your phone keeps a list of working configs.")}</EmptyState>
                ) : (
                    <ul className="divide-y">
                        {tokens.map((tk) => (
                            <li key={String(tk.id)} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                                <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                                <div className="min-w-0 flex-1">
                                    <p className="truncate text-sm font-medium">{tk.name || t("Unnamed link")} <code className="ms-1 font-mono text-xs font-normal text-muted-foreground">{tk.prefix}…</code></p>
                                    <p className="truncate text-xs text-muted-foreground">{describe(tk.defaults ?? {}, subs, t)}</p>
                                </div>
                                <div className="num text-end text-xs text-muted-foreground">
                                    <div>{tk.lastUsedAt ? t("used {when}", { when: formatRelative(tk.lastUsedAt) }) : t("never used")}</div>
                                    <div>{t("{n} requests", { n: tk.useCount ?? 0 })}</div>
                                </div>
                                <div className="flex gap-1">
                                    <Button size="icon-sm" variant="ghost" aria-label={t("Edit {name}", { name: tk.name })} onClick={() => setEdit({ id: tk.id, name: tk.name, d: { ...DEFAULTS, ...tk.defaults } })}><Pencil aria-hidden /></Button>
                                    <Button size="icon-sm" variant="ghost" aria-label={t("Revoke {name}", { name: tk.name })} onClick={() => setRevoke(tk)}><Trash2 aria-hidden /></Button>
                                </div>
                            </li>
                        ))}
                    </ul>
                )}
            </Panel>

            <Dialog open={edit !== null} onOpenChange={(o) => !o && setEdit(null)}>
                <DialogContent className="sm:max-w-lg">
                    <DialogHeader>
                        <DialogTitle>{edit?.id === null ? t("New subscription link") : t("Edit link")}</DialogTitle>
                        <DialogDescription>{t("These are the defaults; a client can override them in the URL query.")}</DialogDescription>
                    </DialogHeader>
                    {edit && (
                        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void save(); }}>
                            <Field id="tk-name" label={t("Name")} hint={t("Shown as the profile title in the client")}>
                                <Input id="tk-name" value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} placeholder={t("My phone")} autoFocus />
                            </Field>
                            <div className="grid grid-cols-2 gap-3">
                                <Field id="tk-format" label={t("Format")}>
                                    <Select value={d.format ?? "base64"} onValueChange={(v) => setD({ format: v as ExportFormat })}>
                                        <SelectTrigger id="tk-format"><SelectValue /></SelectTrigger>
                                        <SelectContent>{EXPORT_FORMATS.map((f) => <SelectItem key={f.value} value={f.value}>{t(f.label)}</SelectItem>)}</SelectContent>
                                    </Select>
                                </Field>
                                <Field id="tk-status" label={t("Include")}>
                                    <Select value={d.status ?? "passed"} onValueChange={(v) => setD({ status: v as SubTokenDefaults["status"] })}>
                                        <SelectTrigger id="tk-status"><SelectValue /></SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="passed">{t("Passed only")}</SelectItem>
                                            <SelectItem value="semi-passed">{t("Passed and semi-passed")}</SelectItem>
                                            <SelectItem value="any">{t("Every config")}</SelectItem>
                                        </SelectContent>
                                    </Select>
                                </Field>
                                <Field id="tk-max" label={t("At most")}>
                                    <InputNumber id="tk-max" label={t("Maximum configs")} min={1} max={5000} step={50} value={d.max ?? 200} onChange={(v) => setD({ max: v })} />
                                </Field>
                                <Field id="tk-int" label={t("Client refresh (hours)")}>
                                    <InputNumber id="tk-int" label={t("Refresh interval")} min={1} max={168} value={d.updateIntervalHours ?? 6} onChange={(v) => setD({ updateIntervalHours: v })} />
                                </Field>
                                {d.status !== "any" && (
                                    <Field id="tk-age" label={t("Tested within (hours)")} hint={t("0 = any time")}>
                                        <InputNumber id="tk-age" label={t("Max age")} min={0} max={24 * 90} value={d.maxAgeHours ?? 0} onChange={(v) => setD({ maxAgeHours: v })} />
                                    </Field>
                                )}
                            </div>
                            {subs.length > 0 && (
                                <fieldset className="space-y-1.5">
                                    <legend className="mb-1 text-[13px] font-medium">{t("Subscriptions")} <span className="font-normal text-muted-foreground">({t("none checked = all enabled")})</span></legend>
                                    <div className="max-h-32 space-y-1 overflow-auto rounded-md border p-2">
                                        {subs.map((s) => {
                                            const on = d.subscriptionIds?.includes(s.id) ?? false;
                                            return (
                                                <label key={s.id} className="flex cursor-pointer items-center gap-2 text-sm">
                                                    <Checkbox checked={on} onCheckedChange={(c) => setD({ subscriptionIds: c ? [...(d.subscriptionIds ?? []), s.id] : (d.subscriptionIds ?? []).filter((x) => x !== s.id) })} />
                                                    <span className="truncate">{s.remark || s.url}</span>
                                                </label>
                                            );
                                        })}
                                    </div>
                                </fieldset>
                            )}
                            <DialogFooter>
                                <Button type="button" variant="secondary" onClick={() => setEdit(null)}>{t("Cancel")}</Button>
                                <Button type="submit" disabled={saving}>{saving && <Loader2 className="animate-spin" aria-hidden />}{edit.id === null ? t("Create link") : t("Save")}</Button>
                            </DialogFooter>
                        </form>
                    )}
                </DialogContent>
            </Dialog>

            <Dialog open={created !== null} onOpenChange={(o) => !o && setCreated(null)}>
                <DialogContent className="sm:max-w-lg">
                    <DialogHeader>
                        <DialogTitle>{t("Your subscription link")}</DialogTitle>
                        <DialogDescription>{t("Copy it now: it is shown only once. Anyone with this URL can read the configs; revoke it if it leaks.")}</DialogDescription>
                    </DialogHeader>
                    {created && (
                        <div className="space-y-3">
                            <div className="flex flex-wrap gap-1" role="group" aria-label={t("Format in the URL")}>
                                {EXPORT_FORMATS.map((f) => (
                                    <button key={f.value} type="button" onClick={() => setCreated({ ...created, format: f.value })} aria-pressed={created.format === f.value}
                                        className={cn("rounded-md border px-2 py-1 text-xs focus-visible:outline-2", created.format === f.value ? "border-primary bg-primary/10 text-primary" : "hover:bg-accent")}>
                                        {t(f.label)}
                                    </button>
                                ))}
                            </div>
                            <p className="break-all rounded-md bg-muted px-2 py-2 font-mono text-xs" dir="ltr">{withFormat(created.url, created.format)}</p>
                            <div className="flex flex-wrap gap-2">
                                <CopyButton text={withFormat(created.url, created.format)} label={t("Copy link")} done={t("Link copied")} size="sm" variant="outline">{t("Copy link")}</CopyButton>
                                <Button size="sm" variant="outline" onClick={() => setQr(withFormat(created.url, created.format))}><QrCode aria-hidden />{t("QR code")}</Button>
                            </div>
                            {loopbackOnly && <Badge variant="semi" className="whitespace-normal">{t("This address only works on this computer.")}</Badge>}
                        </div>
                    )}
                </DialogContent>
            </Dialog>
            <QrDialog open={qr !== null} onOpenChange={(o) => !o && setQr(null)} text={qr ?? ""} title={t("Subscribe with your phone")} />
            <ConfirmDialog open={revoke !== null} onOpenChange={(o) => !o && setRevoke(null)} title={t("Revoke this link?")}
                description={t("Clients using it stop getting updates immediately.")} confirmLabel={t("Revoke")} onConfirm={async () => {
                    if (!revoke) return;
                    try { await api.revokeSubToken(revoke.id); toast.success(t("Link revoked")); load(); }
                    catch (err) { toast.error(t("Could not revoke"), { description: errorMessage(err) }); }
                }} />
        </>
    );
}
