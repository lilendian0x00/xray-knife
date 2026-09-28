import type { DpiResultStatus } from "@/types/dashboard";

export const VERDICTS: Record<string, { title: string; tone: "pass" | "semi" | "fail" | "neutral" }> = {
    "no-interference": { title: "Nothing to work around: the config already gets through", tone: "pass" },
    "fragment-helps": { title: "Fragmentation gets this config through", tone: "pass" },
    partial: { title: "Only unreliable settings got through", tone: "semi" },
    "server-unreachable": { title: "The server can't be reached from this network", tone: "fail" },
    "sni-blocked": { title: "The server's name (SNI) is blocked and no setting helped", tone: "fail" },
    "no-workaround": { title: "Nothing that was tried got through", tone: "fail" },
    canceled: { title: "Stopped before finishing", tone: "neutral" },
};

export const RESULT_STATUS: Record<DpiResultStatus, { label: string; variant: "pass" | "semi" | "fail" | "neutral" }> = {
    pass: { label: "Works", variant: "pass" },
    partial: { label: "Flaky", variant: "semi" },
    fail: { label: "Blocked", variant: "fail" },
    error: { label: "Error", variant: "fail" },
    skipped: { label: "Skipped", variant: "neutral" },
};

export const FAILURE_LABELS: Record<string, string> = {
    timeout: "silent drop",
    reset: "reset",
    refused: "refused",
    eof: "closed early",
    tls: "TLS error",
    dns: "DNS",
    http: "bad HTTP status",
    config: "bad config",
    other: "other",
};

const ORDER: Record<string, number> = { pass: 0, partial: 1, fail: 2, error: 3, skipped: 4 };
export const statusRank = (s: string) => ORDER[s] ?? 9;
