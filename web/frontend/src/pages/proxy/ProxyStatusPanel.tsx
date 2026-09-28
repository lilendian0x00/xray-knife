import { useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { ServerOff, QrCode, Loader2, ArrowRightLeft, Hourglass, AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/common/Panel";
import { CopyButton } from "@/components/common/CopyButton";
import { QrDialog } from "@/components/common/QrDialog";
import { ServiceStateBadge } from "@/components/common/StatusBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useNow } from "@/hooks/useNow";
import type { ProxyDetails } from "@/types/dashboard";
import { errorMessage, formatCountdown, formatMbps, formatMs } from "@/lib/utils";
import { api } from "@/services/api";
import { toast } from "sonner";
import { flag, cleanLocation } from "@/pages/http/resultUtils";
import { useT } from "@/i18n";

function Stat({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd className="num mt-0.5 truncate text-sm font-medium">{children}</dd>
        </div>
    );
}

/** Go's zero time ("0001-01-01T00:00:00Z") means "no timed rotation". */
function rotationDeadline(iso: string | undefined): number | null {
    if (!iso) return null;
    const ms = new Date(iso).getTime();
    return Number.isFinite(ms) && new Date(iso).getUTCFullYear() > 2000 ? ms : null;
}

function RotationBadge({ d }: { d: ProxyDetails }) {
    const t = useT();
    const deadline = rotationDeadline(d.nextRotationTime);
    const now = useNow(1000, d.rotationStatus === "idle" && deadline !== null);
    switch (d.rotationStatus) {
        case "testing": return <Badge variant="info"><Loader2 className="animate-spin" aria-hidden />{t("Testing candidates")}</Badge>;
        case "switching":
        case "rotating": return <Badge variant="info"><ArrowRightLeft aria-hidden />{t("Switching")}</Badge>;
        case "stalled": return <Badge variant="semi"><Hourglass aria-hidden />{t("Stalled: no working config yet")}</Badge>;
        default: {
            if (deadline === null) return <Badge variant="neutral">{t("On failure only")}</Badge>;
            return <Badge variant="neutral" className="num">{t("Next in {t}", { t: formatCountdown((deadline - now) / 1000) })}</Badge>;
        }
    }
}

export function ProxyStatusPanel() {
    const t = useT();
    const { status, details, error } = useRuntimeStore(useShallow((s) => ({ status: s.proxyStatus, details: s.proxyDetails, error: s.proxyError })));
    const [qr, setQr] = useState<string | null>(null);
    const [confirming, setConfirming] = useState(false);

    if (status === "stopped" || !details) {
        return (
            <Panel title={t("Status")} actions={<ServiceStateBadge state={status === "stopped" ? (error ? "error" : "stopped") : status} />}>
                {error && status === "stopped" ? (
                    <div role="alert" className="flex items-start gap-2 rounded-md border border-fail/40 bg-fail/5 p-3 text-sm">
                        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-fail" aria-hidden />
                        <div className="min-w-0"><p className="font-medium">{t("The proxy stopped")}</p><p dir="auto" className="max-h-40 overflow-auto break-words text-muted-foreground">{error}</p></div>
                    </div>
                ) : status === "stopped" ? (
                    <EmptyState icon={ServerOff} title={t("The proxy is not running")}>{t("Paste links, pick a mode and start it. Live details show up here.")}</EmptyState>
                ) : (
                    <EmptyState icon={Loader2} title={status === "starting" ? t("Testing configs to pick the first outbound…") : t("Stopping…")} />
                )}
            </Panel>
        );
    }

    const { inbound, activeOutbound: out } = details;
    const confirmDeadman = async () => {
        setConfirming(true);
        try {
            await api.confirmDeadman();
            toast.success(t("Tunnel confirmed. It stays up."));
        } catch (err) {
            toast.error(t("Could not confirm"), { description: errorMessage(err) });
        } finally {
            setConfirming(false);
        }
    };
    const inboundAddr = `${inbound.Address}:${inbound.Port}`;
    const loc = cleanLocation(out?.location);
    const hops = details.chainHops ?? [];

    return (
        <div className="space-y-4">
            {details.deadmanPending && (
                <div role="alert" className="flex flex-wrap items-center gap-3 rounded-lg border border-semi/50 bg-semi/10 p-3 text-sm">
                    <AlertTriangle className="size-5 shrink-0 text-semi" aria-hidden />
                    <p className="min-w-0 flex-1">{t("The tunnel is up but not confirmed. If this page still works, your connection survived: confirm it, or the tunnel is torn down automatically.")}</p>
                    <Button size="sm" onClick={confirmDeadman} disabled={confirming}>{confirming && <Loader2 className="animate-spin" aria-hidden />}{t("Confirm tunnel")}</Button>
                </div>
            )}
            <Panel title={t("Status")} actions={<ServiceStateBadge state="running" />}>
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <Stat label={t("Listening on")}><span className="font-mono text-[13px]" dir="ltr">{inbound.Protocol?.toLowerCase()}://{inboundAddr}</span></Stat>
                    <Stat label={t("Configs in pool")}>{details.totalConfigs}</Stat>
                    <Stat label={t("Rotation")}>{details.totalConfigs > 1 || details.chainEnabled ? <RotationBadge d={details} /> : <span className="text-muted-foreground">{t("Off (one config)")}</span>}</Stat>
                    <Stat label={t("Interval")}>{rotationDeadline(details.nextRotationTime) === null && details.rotationStatus === "idle" ? t("On failure only") : formatCountdown(details.rotationInterval)}</Stat>
                </dl>
                {inbound.OrigLink && (
                    <div className="mt-4 flex flex-wrap items-center gap-2 rounded-md bg-muted/60 px-3 py-2">
                        <span className="text-xs text-muted-foreground">{t("Connect your apps with")}</span>
                        <code className="min-w-0 flex-1 truncate text-xs" dir="ltr">{inbound.OrigLink}</code>
                        <CopyButton text={inbound.OrigLink} label={t("Copy inbound link")} done={t("Inbound link copied")} />
                        <Button variant="ghost" size="icon-sm" onClick={() => setQr(inbound.OrigLink)} aria-label={t("Show inbound QR code")}><QrCode aria-hidden /></Button>
                    </div>
                )}
            </Panel>

            <Panel title={t("Active outbound")} description={out?.protocol?.remark || undefined}
                actions={out?.link ? <CopyButton text={out.link} label={t("Copy outbound link")} done={t("Link copied")} size="sm" variant="outline">{t("Copy link")}</CopyButton> : undefined}>
                {out && out.protocol ? (
                    <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                        <Stat label={t("Server")}><span className="font-mono text-[13px]" dir="ltr">{out.protocol.protocol} {out.protocol.address}:{out.protocol.port}</span></Stat>
                        <Stat label={t("Delay")}>{formatMs(out.delay)}</Stat>
                        <Stat label={t("Exit")}>{loc ? `${flag(loc)} ${loc}` : "—"}</Stat>
                        <Stat label={t("Speed")}>{out.download > 0 ? t("{down} down", { down: formatMbps(out.download) }) : "—"}</Stat>
                    </dl>
                ) : (
                    <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Waiting for the first working config…")}</p>
                )}
            </Panel>

            {details.chainEnabled && hops.length > 0 && (
                <Panel title={t("Chain")} description={details.chainRotation && details.chainRotation !== "none" ? t("Rotation: {mode}", { mode: details.chainRotation === "exit" ? t("exit hop") : t("whole chain") }) : undefined}>
                    <ol className="relative space-y-3 ps-6">
                        <span aria-hidden className="absolute inset-y-2 start-2 w-px bg-border" />
                        <li className="relative text-xs text-muted-foreground"><span aria-hidden className="absolute -start-[1.15rem] top-1 size-2 rounded-full bg-muted-foreground" />{t("This machine")}</li>
                        {hops.map((h, i) => (
                            <li key={i} className="relative">
                                <span aria-hidden className="absolute -start-[1.2rem] top-1.5 size-2.5 rounded-full border-2 border-primary bg-card" />
                                <div className="flex flex-wrap items-center gap-2 text-sm">
                                    <Badge variant={i === 0 ? "info" : i === hops.length - 1 ? "pass" : "neutral"}>{i === 0 ? t("Entry") : i === hops.length - 1 ? t("Exit") : t("Hop {n}", { n: i + 1 })}</Badge>
                                    <span className="font-mono text-xs md:text-xs" dir="ltr">{h.Protocol} {h.Address}:{h.Port}</span>
                                    {h.Remark && <span className="truncate text-xs text-muted-foreground">{h.Remark}</span>}
                                </div>
                            </li>
                        ))}
                        <li className="relative text-xs text-muted-foreground"><span aria-hidden className="absolute -start-[1.15rem] top-1 size-2 rounded-full bg-pass" />{t("Internet")}</li>
                    </ol>
                </Panel>
            )}
            <QrDialog open={qr !== null} onOpenChange={(o) => !o && setQr(null)} text={qr ?? ""} title={t("Inbound link")} />
        </div>
    );
}
