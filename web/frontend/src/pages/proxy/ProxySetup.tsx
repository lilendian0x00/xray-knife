import { useEffect } from "react";
import { useShallow } from "zustand/react/shallow";
import { Play, Square, Loader2, RotateCcw, RefreshCw, ShieldAlert, Eraser } from "lucide-react";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api, type RestoreResult } from "@/services/api";
import { ApiError } from "@/lib/http";
import { errorMessage } from "@/lib/utils";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Panel } from "@/components/common/Panel";
import { Field, CheckRow } from "@/components/common/Field";
import { Collapsible } from "@/components/common/Collapsible";
import { LinkInput } from "@/components/common/LinkInput";
import { FragmentFields } from "@/components/common/FragmentFields";
import { ConfirmButton } from "@/components/common/ConfirmButton";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useServerStore } from "@/stores/serverStore";
import type { ProxySettings } from "@/types/settings";
import { formatCountdown } from "@/lib/utils";
import { useT } from "@/i18n";

export type ProxySource = "links" | "db";

interface ProxySetupProps {
    links: string;
    setLinks: (v: string) => void;
    linksTooLarge: boolean;
    source: ProxySource;
    setSource: (s: ProxySource) => void;
    onStart: () => void;
    onStop: () => void;
    onRotate: () => void;
    portError: string | null;
}

export function ProxySetup(p: ProxySetupProps) {
    const t = useT();
    const { s, update, reset } = useSettingsStore(useShallow((st) => ({ s: st.proxySettings, update: st.updateProxySettings, reset: st.resetProxySettings })));
    const status = useRuntimeStore((st) => st.proxyStatus);
    const hasSubscriptions = useServerStore((st) => st.hasSubscriptions);
    const hostModes = useServerStore((st) => st.info?.allowHostModes === true);
    const stopped = status === "stopped";
    const hostMode = s.mode === "app" || s.mode === "host-tun";
    // A listener is still created in every mode, but only inbound mode lets you choose its protocol.
    const system = s.mode !== "inbound";
    const [restoring, setRestoring] = useState(false);
    const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null);

    const restore = async (force: boolean) => {
        setRestoring(true);
        try {
            const r = await api.restoreProxy(force);
            setRestoreResult(r);
            if (r.clean && r.removed.length === 0) toast.success(t("Nothing was left behind"));
        } catch (err) {
            const msg = err instanceof ApiError && err.status === 403 ? t("The server was started without --allow-host-modes, so it can't touch host networking.")
                : err instanceof ApiError && err.status === 409 ? t("Stop the proxy first: its own rules would be removed too.")
                : errorMessage(err);
            toast.error(t("Could not restore"), { description: msg });
        } finally {
            setRestoring(false);
        }
    };
    const tlsCapable = !system && (s.inboundProtocol === "vless" || s.inboundProtocol === "vmess");
    const set = <K extends keyof ProxySettings>(k: K) => (v: ProxySettings[K]) => update({ [k]: v } as Partial<ProxySettings>);

    useEffect(() => {
        // gRPC inbounds need TLS.
        if (s.inboundTransport === "grpc" && tlsCapable && !s.enableTls) update({ enableTls: true });
    }, [s.inboundTransport, tlsCapable, s.enableTls, update]);

    const transportField = (key: "ws" | "grpc" | "xhttp", field: string, label: string) => {
        const opts = s.transportOptions[key] as Record<string, string>;
        return (
            <Field id={`px-${key}-${field}`} label={label}>
                <Input id={`px-${key}-${field}`} value={opts[field]} dir="ltr"
                    onChange={(e) => update({ transportOptions: { ...s.transportOptions, [key]: { ...s.transportOptions[key], [field]: e.target.value } } })} />
            </Field>
        );
    };

    const rotationSummary = s.rotationInterval === 0
        ? t("on failure only, max delay {d} ms", { d: s.maximumAllowedDelay })
        : t("every {t}, max delay {d} ms", { t: formatCountdown(s.rotationInterval), d: s.maximumAllowedDelay });
    const inboundSummary = system ? t("managed by this mode") : `${s.inboundProtocol}${s.inboundProtocol !== "socks" ? `/${s.inboundTransport}` : ""}${s.enableTls && tlsCapable ? "+tls" : ""}`;

    return (
        <Panel
            title={t("Local proxy")}
            description={t("Serve a local proxy that rotates through your working configs.")}
            actions={
                <ConfirmButton title={t("Reset proxy settings?")} description={t("All proxy options go back to their defaults. Your links stay.")} confirmLabel={t("Reset")}
                    onConfirm={reset} variant="ghost" size="icon-sm" disabled={!stopped} aria-label={t("Reset proxy settings")}>
                    <RotateCcw aria-hidden />
                </ConfirmButton>
            }
            bodyClassName="space-y-5"
        >
            <fieldset disabled={!stopped} className="space-y-5">
                {hasSubscriptions && (
                    <Field id="px-source" label={t("Config pool")}>
                        <Select value={p.source} onValueChange={(v) => p.setSource(v as ProxySource)}>
                            <SelectTrigger id="px-source"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="links">{t("Pasted links")}</SelectItem>
                                <SelectItem value="db">{t("Enabled subscriptions")}</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                )}
                {p.source === "links" && (
                    <LinkInput id="px-links" label={t("Share links")} value={p.links} onChange={p.setLinks} disabled={!stopped} tooLarge={p.linksTooLarge} rows={6}
                        placeholder={"vless://…\nvmess://…\ntrojan://…"} />
                )}

                <div className="grid grid-cols-2 gap-3">
                    <Field id="px-mode" label={t("Mode")} error={hostMode && !hostModes ? t("This server does not allow host modes (--allow-host-modes).") : null}
                        hint={s.mode === "system" ? t("Points this computer's proxy settings at the local proxy.")
                            : s.mode === "app" ? t("Only programs started with `xray-knife exec` go through the proxy (Linux, root).")
                            : s.mode === "host-tun" ? t("All traffic of the server machine goes through a TUN device (Linux, root).")
                            : t("Only apps you configure use the proxy.")}>
                        <Select value={s.mode} onValueChange={(v) => update({ mode: v as ProxySettings["mode"] })}>
                            <SelectTrigger id="px-mode"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="inbound">{t("Local listener")}</SelectItem>
                                <SelectItem value="system">{t("System proxy")}</SelectItem>
                                {(hostModes || s.mode === "app") && <SelectItem value="app">{t("App tunnel (namespace)")}</SelectItem>}
                                {(hostModes || s.mode === "host-tun") && <SelectItem value="host-tun">{t("Whole machine (TUN)")}</SelectItem>}
                            </SelectContent>
                        </Select>
                    </Field>
                    <Field id="px-core" label={t("Core")}>
                        <Select value={s.coreType} onValueChange={(v) => update({ coreType: v as ProxySettings["coreType"] })}>
                            <SelectTrigger id="px-core"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="xray">Xray</SelectItem>
                                <SelectItem value="sing-box">sing-box</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                    <Field id="px-addr" label={t("Listen address")} hint={s.listenAddr.trim() === "0.0.0.0" || s.listenAddr.trim() === "::" ? t("Reachable from your whole network") : undefined}>
                        <Input id="px-addr" value={s.listenAddr} onChange={(e) => update({ listenAddr: e.target.value })} dir="ltr" className="font-mono" />
                    </Field>
                    <Field id="px-port" label={t("Port")} error={p.portError}>
                        <Input id="px-port" value={s.listenPort} onChange={(e) => update({ listenPort: e.target.value.replace(/[^\d]/g, "").slice(0, 5) })} inputMode="numeric" dir="ltr" className="num font-mono" aria-invalid={!!p.portError} />
                    </Field>
                </div>

                {hostMode && (
                    <div className="space-y-3 rounded-md border border-semi/40 bg-semi/5 p-3">
                        <CheckRow id="px-kill" label={t("Kill switch")} hint={t("Block traffic that would leave outside the tunnel, even if the proxy stops or crashes. SSH and the proxy's own server stay reachable.")}>
                            <Checkbox id="px-kill" checked={s.killSwitch} onCheckedChange={(c) => update({ killSwitch: Boolean(c) })} />
                        </CheckRow>
                        {s.mode === "app" && (
                            <Field id="px-ns" label={t("Namespace name (optional)")} hint={t("Letters, digits, . _ - (up to 32). Empty = automatic.")}>
                                <Input id="px-ns" value={s.namespaceName} onChange={(e) => update({ namespaceName: e.target.value })} dir="ltr" className="font-mono text-xs md:text-xs" />
                            </Field>
                        )}
                        {s.mode === "host-tun" && (
                            <p className="flex items-start gap-2 text-xs text-muted-foreground"><ShieldAlert className="mt-0.5 size-3.5 shrink-0 text-semi" aria-hidden />
                                {t("After it starts you have 60 s to confirm the tunnel on this page; otherwise it is torn down so a broken route can't lock you out.")}</p>
                        )}
                    </div>
                )}

                {!system && (
                    <Collapsible title={t("Inbound")} summary={inboundSummary}>
                        <div className="grid grid-cols-2 gap-3">
                            <Field id="px-in-proto" label={t("Protocol")}>
                                <Select value={s.inboundProtocol} onValueChange={(v) => update({ inboundProtocol: v as ProxySettings["inboundProtocol"] })}>
                                    <SelectTrigger id="px-in-proto"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="socks">SOCKS5</SelectItem>
                                        <SelectItem value="vless">VLESS</SelectItem>
                                        <SelectItem value="vmess">VMess</SelectItem>
                                    </SelectContent>
                                </Select>
                            </Field>
                            <Field id="px-in-transport" label={t("Transport")}>
                                <Select value={s.inboundTransport} onValueChange={(v) => update({ inboundTransport: v as ProxySettings["inboundTransport"] })} disabled={s.inboundProtocol === "socks"}>
                                    <SelectTrigger id="px-in-transport"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="tcp">TCP</SelectItem>
                                        <SelectItem value="ws">WebSocket</SelectItem>
                                        <SelectItem value="grpc">gRPC</SelectItem>
                                        <SelectItem value="xhttp">XHTTP</SelectItem>
                                    </SelectContent>
                                </Select>
                            </Field>
                            {s.inboundProtocol !== "socks" && (
                                <Field id="px-uuid" label={t("UUID")} hint={t('"random" generates one')} className="col-span-2">
                                    <Input id="px-uuid" value={s.inboundUUID} onChange={(e) => update({ inboundUUID: e.target.value })} dir="ltr" className="font-mono text-xs md:text-xs" />
                                </Field>
                            )}
                        </div>
                        {s.inboundProtocol !== "socks" && s.inboundTransport === "ws" && <div className="grid grid-cols-2 gap-3">{transportField("ws", "path", t("Path"))}{transportField("ws", "host", t("Host"))}</div>}
                        {s.inboundProtocol !== "socks" && s.inboundTransport === "grpc" && <div className="grid grid-cols-2 gap-3">{transportField("grpc", "serviceName", t("Service name"))}{transportField("grpc", "authority", t("Authority"))}</div>}
                        {s.inboundProtocol !== "socks" && s.inboundTransport === "xhttp" && <div className="grid grid-cols-3 gap-3">{transportField("xhttp", "mode", t("Mode"))}{transportField("xhttp", "host", t("Host"))}{transportField("xhttp", "path", t("Path"))}</div>}
                        {tlsCapable && (
                            <div className="space-y-3">
                                <CheckRow id="px-tls" label={t("Serve TLS")} hint={s.inboundTransport === "grpc" ? t("Required for gRPC") : undefined}>
                                    <Checkbox id="px-tls" checked={s.enableTls} onCheckedChange={(c) => update({ enableTls: Boolean(c) })} disabled={s.inboundTransport === "grpc"} />
                                </CheckRow>
                                {s.enableTls && (
                                    <div className="grid grid-cols-2 gap-3">
                                        <Field id="px-cert" label={t("Certificate file")}><Input id="px-cert" placeholder="/path/cert.pem" value={s.tlsCertPath} onChange={(e) => update({ tlsCertPath: e.target.value })} dir="ltr" /></Field>
                                        <Field id="px-key" label={t("Key file")}><Input id="px-key" placeholder="/path/key.pem" value={s.tlsKeyPath} onChange={(e) => update({ tlsKeyPath: e.target.value })} dir="ltr" /></Field>
                                        <Field id="px-sni" label="SNI"><Input id="px-sni" placeholder="example.com" value={s.tlsSni} onChange={(e) => update({ tlsSni: e.target.value })} dir="ltr" /></Field>
                                        <Field id="px-alpn" label="ALPN"><Input id="px-alpn" placeholder="h2,http/1.1" value={s.tlsAlpn} onChange={(e) => update({ tlsAlpn: e.target.value })} dir="ltr" /></Field>
                                    </div>
                                )}
                            </div>
                        )}
                    </Collapsible>
                )}

                <Collapsible title={t("Rotation and health")} summary={rotationSummary}>
                    <div className="grid grid-cols-2 gap-3">
                        <Field id="px-rot" label={t("Rotate every (s)")} hint={s.rotationInterval === 0 ? t("0 = only when the current config fails") : formatCountdown(s.rotationInterval)}>
                            <InputNumber id="px-rot" label={t("Rotation interval")} min={0} max={86400 * 7} step={60} value={s.rotationInterval} onChange={set("rotationInterval")} />
                        </Field>
                        <Field id="px-mdelay" label={t("Max delay (ms)")}>
                            <InputNumber id="px-mdelay" label={t("Max delay")} min={100} max={65535} step={500} value={s.maximumAllowedDelay} onChange={set("maximumAllowedDelay")} />
                        </Field>
                        <Field id="px-health" label={t("Health check (s)")} hint={t("0 = off")}>
                            <InputNumber id="px-health" label={t("Health check interval")} min={0} max={86400} step={10} value={s.healthCheckInterval} onChange={set("healthCheckInterval")} />
                        </Field>
                        <Field id="px-hfail" label={t("Failures before switching")} hint={t("0 = automatic")}>
                            <InputNumber id="px-hfail" label={t("Failures before switching")} min={0} max={100} value={s.healthFailThreshold} onChange={set("healthFailThreshold")} />
                        </Field>
                        <Field id="px-batch" label={t("Configs per round")} hint={t("0 = automatic")}>
                            <InputNumber id="px-batch" label={t("Configs per round")} min={0} max={65535} value={s.batchSize} onChange={set("batchSize")} />
                        </Field>
                        <Field id="px-conc" label={t("Test threads")} hint={t("0 = automatic")}>
                            <InputNumber id="px-conc" label={t("Test threads")} min={0} max={1024} value={s.concurrency} onChange={set("concurrency")} />
                        </Field>
                        <Field id="px-drain" label={t("Drain time (s)")} hint={t("Keep old connections before switching")}>
                            <InputNumber id="px-drain" label={t("Drain time")} min={0} max={3600} value={s.drainTimeout} onChange={set("drainTimeout")} />
                        </Field>
                        <Field id="px-bl" label={t("Blacklist after N failures")} hint={t("0 = off")}>
                            <InputNumber id="px-bl" label={t("Blacklist strikes")} min={0} max={100} value={s.blacklistStrikes} onChange={set("blacklistStrikes")} />
                        </Field>
                        {s.blacklistStrikes > 0 && (
                            <Field id="px-bld" label={t("Blacklist for (s)")}>
                                <InputNumber id="px-bld" label={t("Blacklist duration")} min={0} max={86400 * 7} step={60} value={s.blacklistDuration} onChange={set("blacklistDuration")} />
                            </Field>
                        )}
                    </div>
                    <Field id="px-hurl" label={t("Health-check URL")} hint={t("Fetched through the proxy to decide whether the outbound still works. Empty = Cloudflare trace.")}>
                        <Input id="px-hurl" value={s.healthCheckUrl} onChange={(e) => update({ healthCheckUrl: e.target.value })} placeholder="https://cloudflare.com/cdn-cgi/trace" dir="ltr" className="font-mono text-xs md:text-xs" inputMode="url" />
                    </Field>
                    <CheckRow id="px-insecure" label={t("Allow insecure TLS on outbounds")}>
                        <Checkbox id="px-insecure" checked={s.insecureTLS} onCheckedChange={(c) => update({ insecureTLS: Boolean(c) })} />
                    </CheckRow>
                </Collapsible>

                <Collapsible title={t("Multi-hop chain")} summary={s.chain ? t("{n} hops, {mode} rotation", { n: s.chainHops, mode: s.chainRotation }) : t("Off")}>
                    <CheckRow id="px-chain" label={t("Route through several proxies in a row")} hint={t("The first hop is dialed from here; the last hop reaches the internet.")}>
                        <Checkbox id="px-chain" checked={s.chain} onCheckedChange={(c) => update({ chain: Boolean(c) })} />
                    </CheckRow>
                    {s.chain && (
                        <>
                            <div className="grid grid-cols-2 gap-3">
                                <Field id="px-hops" label={t("Hops")}>
                                    <InputNumber id="px-hops" label={t("Hops")} min={2} max={10} value={s.chainHops} onChange={set("chainHops")} />
                                </Field>
                                <Field id="px-chain-rot" label={t("Rotate")}>
                                    <Select value={s.chainRotation} onValueChange={(v) => update({ chainRotation: v as ProxySettings["chainRotation"] })}>
                                        <SelectTrigger id="px-chain-rot"><SelectValue /></SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="none">{t("Never")}</SelectItem>
                                            <SelectItem value="exit">{t("Exit hop only")}</SelectItem>
                                            <SelectItem value="full">{t("Whole chain")}</SelectItem>
                                        </SelectContent>
                                    </Select>
                                </Field>
                                <Field id="px-chain-att" label={t("Attempts to build a chain")} hint={t("0 = 5")}>
                                    <InputNumber id="px-chain-att" label={t("Chain attempts")} min={0} max={100} value={s.chainAttempts} onChange={set("chainAttempts")} />
                                </Field>
                            </div>
                            <Field id="px-chain-links" label={t("Fixed chain (optional)")} hint={t("Links separated by |, entry first. When set, the pool is not used and rotation is off.")}>
                                <Textarea id="px-chain-links" rows={3} value={s.chainLinks} onChange={(e) => update({ chainLinks: e.target.value })} placeholder="vless://entry…|trojan://exit…" dir="ltr" className="font-mono text-xs md:text-xs" spellCheck={false} />
                            </Field>
                        </>
                    )}
                </Collapsible>

                <FragmentFields idPrefix="px" value={s.fragment} onChange={(fragment) => update({ fragment })} disabled={!stopped} core={s.coreType} />
            </fieldset>

            {hostModes && (
                <div className="flex items-center justify-between gap-2 border-t pt-3 text-xs text-muted-foreground">
                    <span>{t("A crashed app or TUN run can leave routes, rules or proxy settings behind.")}</span>
                    <ConfirmButton title={t("Restore host networking?")} description={t("Removes kill-switch rules, TUN routes, network namespaces and OS proxy settings left by a crashed run. Items still used by a running process are kept unless you force it.")}
                        confirmLabel={t("Restore")} destructive={false} onConfirm={() => restore(false)} variant="ghost" size="sm" disabled={!stopped || restoring} className="shrink-0">
                        {restoring ? <Loader2 className="animate-spin" aria-hidden /> : <Eraser aria-hidden />}{t("Restore leftovers")}
                    </ConfirmButton>
                </div>
            )}
            <Dialog open={restoreResult !== null && !(restoreResult.clean && restoreResult.removed.length === 0)} onOpenChange={(o) => !o && setRestoreResult(null)}>
                <DialogContent className="sm:max-w-lg">
                    <DialogHeader>
                        <DialogTitle>{restoreResult?.clean ? t("Host networking restored") : t("Some leftovers remain")}</DialogTitle>
                        <DialogDescription>{t("What the cleanup found from earlier app or TUN runs.")}</DialogDescription>
                    </DialogHeader>
                    {restoreResult && (
                        <div className="space-y-3 text-sm">
                            {([["Removed", restoreResult.removed, "text-pass"], ["Kept (still owned by a live process)", restoreResult.kept, "text-semi"], ["Errors", restoreResult.errors, "text-fail"]] as const).map(([label, list, tone]) => list.length > 0 && (
                                <div key={label}>
                                    <p className={`font-medium ${tone}`}>{t(label)} ({list.length})</p>
                                    <ul className="mt-1 max-h-28 overflow-auto rounded bg-muted p-2 font-mono text-[11px]" dir="ltr">{list.map((x, i) => <li key={i}>{x}</li>)}</ul>
                                </div>
                            ))}
                        </div>
                    )}
                    <DialogFooter>
                        {restoreResult && restoreResult.kept.length > 0 && (
                            <Button variant="destructive" disabled={restoring} onClick={() => restore(true)}>{t("Force remove kept items")}</Button>
                        )}
                        <Button variant="secondary" onClick={() => setRestoreResult(null)}>{t("Close")}</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <div className="flex gap-2">
                {stopped ? (
                    <Button className="flex-1" onClick={p.onStart}><Play aria-hidden />{t("Start proxy")}</Button>
                ) : (
                    <Button className="flex-1" disabled={status !== "running"} variant={status === "running" ? "secondary" : "default"} onClick={p.onRotate}>
                        {status === "running" ? <><RefreshCw aria-hidden />{t("Rotate now")}</> : <><Loader2 className="animate-spin" aria-hidden />{status === "starting" ? t("Starting…") : t("Stopping…")}</>}
                    </Button>
                )}
                <ConfirmButton title={t("Stop the proxy?")} description={t("Open connections through it are closed.")} confirmLabel={t("Stop")} onConfirm={p.onStop}
                    variant="stop" size="default" disabled={status !== "running" && status !== "starting"}>
                    <Square aria-hidden />{t("Stop")}
                </ConfirmButton>
            </div>
        </Panel>
    );
}
