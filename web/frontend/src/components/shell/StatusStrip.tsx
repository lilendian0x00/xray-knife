import { useShallow } from "zustand/react/shallow";
import { Globe, Server, Radar } from "lucide-react";
import { useRuntimeStore, type TaskStatus } from "@/stores/runtimeStore";
import type { Page } from "@/hooks/useHashRoute";
import { cn } from "@/lib/utils";
import { useT } from "@/i18n";
import type { ProxyStatus, Progress } from "@/types/dashboard";

interface SegmentProps {
    icon: typeof Globe;
    name: string;
    state: string;
    tone: "on" | "busy" | "off" | "error";
    progress?: number | null;
    onClick: () => void;
    active: boolean;
}

function Segment({ icon: Icon, name, state, tone, progress, onClick, active }: SegmentProps) {
    return (
        <button
            type="button"
            onClick={onClick}
            aria-current={active ? "page" : undefined}
            className={cn(
                "group relative flex min-w-0 flex-1 items-center gap-2 overflow-hidden rounded-md border px-2.5 py-1.5 text-start text-xs transition-colors hover:bg-accent/70 focus-visible:outline-2 sm:flex-none",
                active ? "border-primary/40 bg-primary/5" : "border-transparent",
            )}
        >
            <Icon aria-hidden className={cn("size-4 shrink-0", tone === "on" ? "text-pass" : tone === "busy" ? "text-primary" : tone === "error" ? "text-fail" : "text-muted-foreground")} />
            <span className="min-w-0">
                <span className="block truncate font-medium leading-4">{name}</span>
                <span className={cn("num block truncate leading-4", tone === "error" ? "text-fail" : "text-muted-foreground")}>{state}</span>
            </span>
            {progress != null && (
                <span className="absolute inset-x-0 bottom-0 h-0.5 bg-primary/15" aria-hidden>
                    <span className="block h-full bg-primary transition-[width] duration-500" style={{ width: `${Math.round(progress * 100)}%` }} />
                </span>
            )}
        </button>
    );
}

function taskLabel(t: ReturnType<typeof useT>, s: TaskStatus, p: Progress, error: string | null): { text: string; tone: SegmentProps["tone"]; progress: number | null } {
    if (s === "idle") return error ? { text: t("Failed"), tone: "error", progress: null } : { text: t("Idle"), tone: "off", progress: null };
    if (s === "starting") return { text: t("Starting"), tone: "busy", progress: null };
    if (s === "stopping") return { text: t("Stopping"), tone: "busy", progress: null };
    const frac = p.total > 0 ? p.completed / p.total : null;
    return { text: frac != null ? `${p.completed}/${p.total} (${Math.floor(frac * 100)}%)` : t("Running"), tone: "busy", progress: frac };
}

function proxyLabel(t: ReturnType<typeof useT>, s: ProxyStatus, error: string | null) {
    if (s === "running") return { text: t("Running"), tone: "on" as const };
    if (s === "starting") return { text: t("Starting"), tone: "busy" as const };
    if (s === "stopping") return { text: t("Stopping"), tone: "busy" as const };
    return error ? { text: t("Failed"), tone: "error" as const } : { text: t("Stopped"), tone: "off" as const };
}

export function StatusStrip({ page, navigate }: { page: Page; navigate: (p: Page) => void }) {
    const t = useT();
    const s = useRuntimeStore(useShallow((st) => ({
        proxyStatus: st.proxyStatus, proxyError: st.proxyError,
        httpStatus: st.httpStatus, httpProgress: st.httpProgress, httpError: st.httpError,
        scanStatus: st.scanStatus, scanProgress: st.scanProgress, scanError: st.scanError,
    })));
    const proxy = proxyLabel(t, s.proxyStatus, s.proxyError);
    const http = taskLabel(t, s.httpStatus, s.httpProgress, s.httpError);
    const scan = taskLabel(t, s.scanStatus, s.scanProgress, s.scanError);
    return (
        <nav aria-label={t("Service status")} className="flex min-w-0 items-stretch gap-1">
            <Segment icon={Server} name={t("Proxy")} state={proxy.text} tone={proxy.tone} onClick={() => navigate("proxy")} active={page === "proxy"} />
            <Segment icon={Globe} name={t("HTTP test")} state={http.text} tone={http.tone} progress={http.progress} onClick={() => navigate("http")} active={page === "http"} />
            <Segment icon={Radar} name={t("CF scan")} state={scan.text} tone={scan.tone} progress={scan.progress} onClick={() => navigate("cf")} active={page === "cf"} />
        </nav>
    );
}
