import { useState } from "react";
import { QrCode, RotateCw } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ResultStatusBadge } from "@/components/common/StatusBadge";
import { CopyButton } from "@/components/common/CopyButton";
import { QrDialog } from "@/components/common/QrDialog";
import type { HttpResult } from "@/types/dashboard";
import { formatMbps, formatMs, cn } from "@/lib/utils";
import { cleanIp, cleanLocation, failureLabel, FAILURE_KINDS, flag, resultName, resultProtocol } from "./resultUtils";
import { useT } from "@/i18n";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div className="grid grid-cols-[8.5rem_1fr] gap-3 py-1.5 text-sm">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="num min-w-0 break-words">{children}</dd>
        </div>
    );
}

const OUTCOME_CLASS: Record<string, string> = { ok: "text-pass", slow: "text-semi", "bad-status": "text-fail", error: "text-fail" };

export function ResultDetails({ result, onClose, onRetest, canRetest }: { result: HttpResult | null; onClose: () => void; onRetest: (link: string) => void; canRetest: boolean }) {
    const t = useT();
    const [qr, setQr] = useState(false);
    if (!result) return null;
    const r = result;
    const loc = cleanLocation(r.location);
    const ip = cleanIp(r.ip);
    const hasRtt = (r.rttSamples ?? 0) > 0;
    return (
        <>
            <Dialog open={!!result} onOpenChange={(o) => !o && onClose()}>
                <DialogContent className="sm:max-w-2xl">
                    <DialogHeader>
                        <DialogTitle className="flex flex-wrap items-center gap-2 pe-6">
                            <span className="min-w-0 truncate">{resultName(r) || t("Config")}</span>
                            <ResultStatusBadge status={r.status} />
                        </DialogTitle>
                        <DialogDescription>{resultProtocol(r)}{r.protocol?.address ? ` ${r.protocol.address}:${r.protocol.port}` : ""}</DialogDescription>
                    </DialogHeader>
                    <dl className="divide-y">
                        {r.failureKind && (
                            <Row label={t("Failure")}>
                                <span className="font-medium text-fail">{t(failureLabel(r.failureKind))}</span>
                                {FAILURE_KINDS[r.failureKind] && <span className="block text-xs text-muted-foreground">{t(FAILURE_KINDS[r.failureKind].hint)}</span>}
                            </Row>
                        )}
                        {r.reason && <Row label={t("Reason")}><span dir="auto" className={cn("break-words", r.status !== "passed" && "text-fail")}>{r.reason}</span></Row>}
                        <Row label={t("Delay")}>{formatMs(r.delay)}</Row>
                        {(r.ttfb ?? 0) > 0 && <Row label={t("First byte")}>{formatMs(r.ttfb)}</Row>}
                        {(r.connectTime ?? 0) > 0 && <Row label={t("Connect")}>{formatMs(r.connectTime)}</Row>}
                        {(r.code ?? 0) > 0 && <Row label={t("HTTP status")}>{r.code}</Row>}
                        {hasRtt && (
                            <Row label={t("Round trips")}>
                                {t("min {min}, avg {avg}, max {max}, jitter {jitter} ({n} samples)", {
                                    min: formatMs(r.rttMin), avg: formatMs(r.rttAvg), max: formatMs(r.rttMax), jitter: formatMs(r.jitter), n: r.rttSamples ?? 0,
                                })}
                            </Row>
                        )}
                        {(r.download > 0 || r.upload > 0) && <Row label={t("Speed")}>{t("{down} down, {up} up", { down: formatMbps(r.download), up: formatMbps(r.upload) })}</Row>}
                        {(ip || loc) && <Row label={t("Exit")}>{loc && <span className="me-2">{flag(loc)} {loc}</span>}{r.colo && <span className="me-2 text-muted-foreground">{r.colo}</span>}{r.warp && r.warp !== "off" && <span className="me-2 text-info">WARP {r.warp}</span>}<span className="font-mono text-xs md:text-xs">{ip}</span></Row>}
                        {r.tls && <Row label={t("Security")}>{r.tls}</Row>}
                        {r.fragment && <Row label={t("Fragment")}><span className="font-mono text-xs md:text-xs">{r.fragment}</span></Row>}
                    </dl>
                    {r.endpoints && r.endpoints.length > 0 && (
                        <div className="space-y-2">
                            <p className="text-sm font-medium">{t("Endpoints ({ok} of {total} passed)", { ok: r.successCount ?? 0, total: r.totalCount ?? r.endpoints.length })}</p>
                            <div className="overflow-x-auto rounded-md border">
                                <table className="w-full text-xs">
                                    <thead className="bg-muted/60 text-muted-foreground">
                                        <tr><th scope="col" className="px-2 py-1.5 text-start font-medium">{t("Site")}</th><th scope="col" className="px-2 py-1.5 text-start font-medium">{t("Result")}</th><th scope="col" className="px-2 py-1.5 text-end font-medium">{t("Code")}</th><th scope="col" className="px-2 py-1.5 text-end font-medium">{t("Delay")}</th></tr>
                                    </thead>
                                    <tbody className="divide-y">
                                        {r.endpoints.map((e, i) => (
                                            <tr key={i}>
                                                <td className="px-2 py-1.5" title={e.url}>{e.label || e.url}</td>
                                                <td className={cn("px-2 py-1.5", OUTCOME_CLASS[e.outcome])}>{e.outcome}{e.reason ? `: ${e.reason}` : ""}</td>
                                                <td className="num px-2 py-1.5 text-end">{e.code > 0 ? e.code : "—"}</td>
                                                <td className="num px-2 py-1.5 text-end">{formatMs(e.delay)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    <div className="space-y-2">
                        <p className="text-sm font-medium">{t("Share link")}</p>
                        <p className="max-h-24 overflow-auto break-all rounded-md bg-muted px-2 py-1.5 font-mono text-[11px]" dir="ltr">{r.link}</p>
                        <div className="flex flex-wrap gap-2">
                            <CopyButton text={r.link} label={t("Copy link")} done={t("Link copied")} size="sm" variant="outline">{t("Copy link")}</CopyButton>
                            <Button size="sm" variant="outline" onClick={() => setQr(true)}><QrCode aria-hidden />{t("QR code")}</Button>
                            <Button size="sm" variant="outline" disabled={!canRetest} onClick={() => onRetest(r.link)} title={canRetest ? undefined : t("Wait for the current test to finish")}>
                                <RotateCw aria-hidden />{t("Test again")}
                            </Button>
                        </div>
                    </div>
                </DialogContent>
            </Dialog>
            <QrDialog open={qr} onOpenChange={setQr} text={r.link} />
        </>
    );
}
