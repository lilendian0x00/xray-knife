import { CircleCheck, CircleAlert, CircleX, CircleDashed, Loader2, CircleSlash } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { HttpStatus } from "@/types/dashboard";
import { useT } from "@/i18n";

const MAP: Record<string, { variant: "pass" | "semi" | "fail" | "neutral"; icon: typeof CircleCheck; label: string }> = {
    passed: { variant: "pass", icon: CircleCheck, label: "Passed" },
    "semi-passed": { variant: "semi", icon: CircleAlert, label: "Semi-passed" },
    failed: { variant: "fail", icon: CircleX, label: "Failed" },
    broken: { variant: "fail", icon: CircleSlash, label: "Broken" },
    timeout: { variant: "fail", icon: CircleX, label: "Timeout" },
    canceled: { variant: "neutral", icon: CircleDashed, label: "Canceled" },
};

/** `compact` collapses to the icon in narrow containers (the label stays for screen readers). */
export function ResultStatusBadge({ status, compact }: { status: HttpStatus | string; compact?: boolean }) {
    const t = useT();
    const m = MAP[status] ?? { variant: "neutral" as const, icon: CircleDashed, label: status };
    const Icon = m.icon;
    return (
        <Badge variant={m.variant} className={compact ? "gap-1 font-medium @max-lg:px-1" : "gap-1 font-medium"} title={t(m.label)}>
            <Icon aria-hidden /><span className={compact ? "@max-lg:sr-only" : undefined}>{t(m.label)}</span>
        </Badge>
    );
}

export type ServiceState = "idle" | "starting" | "running" | "stopping" | "stopped" | "error";

/** Service state as text + colour + icon (never colour alone). */
export function ServiceStateBadge({ state, label }: { state: ServiceState; label?: string }) {
    const t = useT();
    const busy = state === "starting" || state === "stopping";
    const variant = state === "running" ? "pass" : state === "error" ? "fail" : busy ? "info" : "neutral";
    const text = label ?? {
        idle: t("Idle"), stopped: t("Stopped"), starting: t("Starting"), stopping: t("Stopping"), running: t("Running"), error: t("Error"),
    }[state];
    return (
        <Badge variant={variant} className="gap-1.5">
            {busy ? <Loader2 className="animate-spin" aria-hidden /> : <span aria-hidden className={`size-1.5 rounded-full ${state === "running" ? "bg-pass" : state === "error" ? "bg-fail" : "bg-muted-foreground/60"}`} />}
            {text}
        </Badge>
    );
}
