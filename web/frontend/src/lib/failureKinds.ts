// Plain-language names for pkg/http Result.failureKind (blocked-vs-dead
// diagnostics). Kept out of the page chunks: the event service uses it for
// the "finished" toast.

export type FailureGroup = "sni" | "dns" | "unreachable" | "server" | "slow" | "other";

export const FAILURE_KINDS: Record<string, { label: string; hint: string; group: FailureGroup }> = {
    "config": { label: "Bad config", hint: "The link could not be parsed or is not supported.", group: "other" },
    "dns": { label: "DNS failed", hint: "The server's name did not resolve.", group: "dns" },
    "dns-poisoned": { label: "DNS poisoned", hint: "The resolver returned a fake or private address: the name is censored. Set a resolver (DoH) in the advanced options.", group: "dns" },
    "tcp-refused": { label: "Refused", hint: "Nothing accepts connections on that port, or the network rejects it.", group: "unreachable" },
    "tcp-timeout": { label: "No answer", hint: "Packets are silently dropped: the IP or port is blocked, or the server is down.", group: "unreachable" },
    "tcp-reset": { label: "TCP reset", hint: "The connection was cut right after it opened.", group: "unreachable" },
    "tcp-unreachable": { label: "Unreachable", hint: "No route to the server from this network.", group: "unreachable" },
    "tls-reset": { label: "TLS reset", hint: "Cut during the TLS handshake: typical SNI filtering. Try the DPI finder.", group: "sni" },
    "tls-timeout": { label: "TLS stalled", hint: "The handshake never finished: often DPI dropping the ClientHello. Try the DPI finder.", group: "sni" },
    "tls-cert": { label: "Certificate", hint: "The certificate did not verify. Check SNI or allow insecure TLS.", group: "server" },
    "proxy-auth": { label: "Rejected", hint: "The server refused the credentials: expired or wrong UUID/password.", group: "server" },
    "proxy-protocol": { label: "Protocol mismatch", hint: "The server answered, but not in the protocol the link describes.", group: "server" },
    "proxy-timeout": { label: "Proxy stalled", hint: "Connected to the server but the tunnel never came up.", group: "server" },
    "http-status": { label: "Wrong status", hint: "The tunnel works but the test site answered unexpectedly.", group: "other" },
    "http-timeout": { label: "Request timed out", hint: "The tunnel opened but the test request did not finish in time.", group: "slow" },
    "slow": { label: "Too slow", hint: "It works, but slower than the max delay.", group: "slow" },
    "canceled": { label: "Canceled", hint: "The run was stopped before this config finished.", group: "other" },
    "other": { label: "Other", hint: "An error that does not fit the categories above; see the reason.", group: "other" },
};

export const FAILURE_GROUPS: Record<FailureGroup, string> = {
    sni: "SNI blocked: try the DPI finder",
    dns: "DNS problem: set a resolver",
    unreachable: "Server or IP unreachable",
    server: "Server-side or config problem",
    slow: "Too slow",
    other: "Other",
};

export function failureLabel(kind: string | undefined): string {
    if (!kind) return "";
    return FAILURE_KINDS[kind]?.label ?? kind;
}
