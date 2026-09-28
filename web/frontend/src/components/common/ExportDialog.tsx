import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Download, Eye, Loader2, AlertTriangle } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Field, CheckRow } from "./Field";
import { CopyButton } from "./CopyButton";
import { api, type ExportFormat, type ExportQuery, type ExportReport } from "@/services/api";
import { useServerStore } from "@/stores/serverStore";
import { usePersistentState } from "@/hooks/usePersistentState";
import { ApiError } from "@/lib/http";
import { errorMessage, formatCount } from "@/lib/utils";
import { useT } from "@/i18n";
import { EXPORT_FORMATS } from "@/lib/exportFormats";



const DEFAULT_QUERY: ExportQuery = { format: "base64", status: "passed", protocol: "", limit: 0, maxAgeHours: 0, insecure: false };

interface ExportDialogProps {
    open: boolean;
    onOpenChange: (o: boolean) => void;
    /** Subscription ids, or "all" for every enabled subscription. */
    target: number[] | "all";
    title: string;
}

export function ExportDialog({ open, onOpenChange, target, title }: ExportDialogProps) {
    const t = useT();
    // Select the stable array, derive in render: a selector returning a fresh
    // array would re-render forever.
    const infoProtocols = useServerStore((s) => s.info?.protocols);
    const protocols = infoProtocols?.map((p) => p.scheme) ?? ["vless", "vmess", "trojan", "ss", "hysteria2", "tuic", "wireguard"];
    const [saved, setSaved] = usePersistentState<ExportQuery>("export-query", DEFAULT_QUERY);
    const q = { ...DEFAULT_QUERY, ...saved };
    const set = (patch: Partial<ExportQuery>) => { setSaved({ ...q, ...patch }); setReport(null); setProblem(null); };
    const [report, setReport] = useState<ExportReport | null>(null);
    const [problem, setProblem] = useState<{ text: string; skipped?: ExportReport["skipped"] } | null>(null);
    const [busy, setBusy] = useState<"preview" | "download" | null>(null);

    useEffect(() => { if (!open) { setReport(null); setProblem(null); } }, [open]);

    const explain = (err: unknown) => {
        if (err instanceof ApiError && err.status === 404) {
            setProblem({ text: q.status === "any" ? t("No stored configs match these filters.") : t("No config matches: nothing has passed a test yet, or the last test is older than the age limit. Test the subscription first or choose \"any status\".") });
        } else if (err instanceof ApiError && err.status === 422) {
            const body = err.body as { skipped?: ExportReport["skipped"] } | undefined;
            setProblem({ text: t("Configs matched, but none can be written as {format}.", { format: q.format }), skipped: body?.skipped });
        } else {
            setProblem({ text: errorMessage(err) });
        }
    };

    const preview = async () => {
        setBusy("preview");
        try {
            setReport(await api.exportReport(target, q));
            setProblem(null);
        } catch (err) {
            setReport(null);
            explain(err);
        } finally {
            setBusy(null);
        }
    };

    const downloadFile = async () => {
        setBusy("download");
        try {
            const d = await api.exportFile(target, q);
            const url = URL.createObjectURL(d.blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = d.filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
            const conv = d.headers.get("X-Export-Converted");
            const skip = Number(d.headers.get("X-Export-Skipped") ?? 0);
            toast.success(t("Exported {n} configs", { n: conv ?? "?" }), { description: skip > 0 ? t("{n} could not be converted to this format", { n: skip }) : undefined });
        } catch (err) {
            explain(err);
        } finally {
            setBusy(null);
        }
    };

    const fmt = EXPORT_FORMATS.find((f) => f.value === q.format);
    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-xl">
                <DialogHeader>
                    <DialogTitle>{title}</DialogTitle>
                    <DialogDescription>{t("Writes the stored configs in a format your client imports. Tested configs come first, fastest first.")}</DialogDescription>
                </DialogHeader>
                <div className="grid grid-cols-2 gap-3">
                    <Field id="ex-format" label={t("Format")} hint={fmt ? t(fmt.hint) : undefined} className="col-span-2 sm:col-span-1">
                        <Select value={q.format} onValueChange={(v) => set({ format: v as ExportFormat })}>
                            <SelectTrigger id="ex-format"><SelectValue /></SelectTrigger>
                            <SelectContent>{EXPORT_FORMATS.map((f) => <SelectItem key={f.value} value={f.value}>{t(f.label)}</SelectItem>)}</SelectContent>
                        </Select>
                    </Field>
                    <Field id="ex-status" label={t("Include")} hint={t("Based on each config's latest test")} className="col-span-2 sm:col-span-1">
                        <Select value={q.status} onValueChange={(v) => set({ status: v as ExportQuery["status"] })}>
                            <SelectTrigger id="ex-status"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="passed">{t("Passed only")}</SelectItem>
                                <SelectItem value="semi-passed">{t("Passed and semi-passed")}</SelectItem>
                                <SelectItem value="any">{t("Every config (tested or not)")}</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                    <Field id="ex-proto" label={t("Protocol")}>
                        <Select value={q.protocol || "all"} onValueChange={(v) => set({ protocol: v === "all" ? "" : v })}>
                            <SelectTrigger id="ex-proto"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="all">{t("All protocols")}</SelectItem>
                                {protocols.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                            </SelectContent>
                        </Select>
                    </Field>
                    <Field id="ex-limit" label={t("At most")} hint={t("0 = 5000")}>
                        <InputNumber id="ex-limit" label={t("Export limit")} min={0} max={5000} step={50} value={q.limit ?? 0} onChange={(v) => set({ limit: v })} />
                    </Field>
                    {q.status !== "any" && (
                        <Field id="ex-age" label={t("Tested within (hours)")} hint={t("0 = any time")}>
                            <InputNumber id="ex-age" label={t("Max age")} min={0} max={24 * 90} value={q.maxAgeHours ?? 0} onChange={(v) => set({ maxAgeHours: v })} />
                        </Field>
                    )}
                    {q.format === "singbox" && (
                        <div className="col-span-2">
                            <CheckRow id="ex-insecure" label={t("Skip certificate checks in the sing-box config")}>
                                <Checkbox id="ex-insecure" checked={!!q.insecure} onCheckedChange={(c) => set({ insecure: Boolean(c) })} />
                            </CheckRow>
                        </div>
                    )}
                </div>

                {problem && (
                    <div role="alert" className="space-y-2 rounded-md border border-semi/40 bg-semi/10 p-3 text-sm">
                        <p className="flex items-start gap-2"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-semi" aria-hidden />{problem.text}</p>
                        {problem.skipped && problem.skipped.length > 0 && <SkipList items={problem.skipped} />}
                    </div>
                )}
                {report && (
                    <div className="space-y-2 rounded-md border p-3">
                        <p className="num text-sm">
                            {t("{c} of {s} selected configs converted", { c: formatCount(report.converted), s: formatCount(report.selected) })}
                            {report.skipped.length > 0 && <span className="text-semi">{t(", {n} skipped", { n: report.skipped.length })}</span>}
                        </p>
                        {report.skipped.length > 0 && <SkipList items={report.skipped} />}
                        <pre className="max-h-40 overflow-auto rounded bg-muted p-2 font-mono text-[11px] leading-4" dir="ltr">{report.content.slice(0, 4000)}{report.content.length > 4000 ? "\n…" : ""}</pre>
                        <CopyButton text={report.content} label={t("Copy the export")} done={t("Export copied")} size="sm" variant="outline">{t("Copy")}</CopyButton>
                    </div>
                )}
                <DialogFooter>
                    <Button variant="outline" onClick={preview} disabled={busy !== null}>{busy === "preview" ? <Loader2 className="animate-spin" aria-hidden /> : <Eye aria-hidden />}{t("Preview")}</Button>
                    <Button onClick={downloadFile} disabled={busy !== null}>{busy === "download" ? <Loader2 className="animate-spin" aria-hidden /> : <Download aria-hidden />}{t("Download")}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

function SkipList({ items }: { items: ExportReport["skipped"] }) {
    const t = useT();
    const shown = items.slice(0, 50);
    return (
        <details className="text-xs">
            <summary className="cursor-pointer text-muted-foreground">{t("Why {n} configs were skipped", { n: items.length })}</summary>
            <ul className="mt-1 max-h-32 space-y-0.5 overflow-auto">
                {shown.map((s, i) => <li key={i} className="truncate"><span className="font-medium">{s.name || `#${s.index}`}</span>: <span className="text-muted-foreground">{s.reason}</span></li>)}
                {items.length > shown.length && <li className="text-muted-foreground">{t("and {n} more", { n: items.length - shown.length })}</li>}
            </ul>
        </details>
    );
}
