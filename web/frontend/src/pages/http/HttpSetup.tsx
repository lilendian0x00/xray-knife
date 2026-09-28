import { useEffect, useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { Play, Square, Loader2, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Progress } from "@/components/ui/progress";
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
import { events, type HttpPhase } from "@/services/events";
import { api, type Subscription } from "@/services/api";
import type { CheckPreset, HttpTesterSettings } from "@/types/settings";
import { formatCount } from "@/lib/utils";
import { useT } from "@/i18n";

export type LinkSource = "links" | "subscription" | "db";

interface HttpSetupProps {
    links: string;
    setLinks: (v: string) => void;
    linksTooLarge: boolean;
    source: LinkSource;
    setSource: (s: LinkSource) => void;
    subscriptionId: number | null;
    setSubscriptionId: (id: number | null) => void;
    onRun: () => void;
    onStop: () => void;
}

const PRESET_LABELS: Record<Exclude<CheckPreset, "none" | "custom">, string> = {
    cloudflare: "Cloudflare trace",
    gstatic: "Google 204",
    global: "Global panel (4 sites)",
    google: "Google services",
    streaming: "Streaming",
};

function usePhase() {
    const [phase, setPhase] = useState<HttpPhase | null>(null);
    useEffect(() => events.onPhase(setPhase), []);
    return phase;
}

export function HttpSetup(p: HttpSetupProps) {
    const t = useT();
    const { s, update, reset } = useSettingsStore(useShallow((st) => ({ s: st.httpSettings, update: st.updateHttpSettings, reset: st.resetHttpSettings })));
    const { status, progress } = useRuntimeStore(useShallow((st) => ({ status: st.httpStatus, progress: st.httpProgress })));
    const { hasSubscriptions, info } = useServerStore(useShallow((st) => ({ hasSubscriptions: st.hasSubscriptions, info: st.info })));
    const [subs, setSubs] = useState<Subscription[]>([]);
    const phase = usePhase();
    const busy = status !== "idle";
    const maxThreads = info?.limits?.maxThreads ?? 2048;

    useEffect(() => {
        if (hasSubscriptions && p.source !== "links") api.subscriptions().then(setSubs).catch(() => setSubs([]));
    }, [hasSubscriptions, p.source]);

    const set = <K extends keyof HttpTesterSettings>(k: K) => (v: HttpTesterSettings[K]) => update({ [k]: v } as Partial<HttpTesterSettings>);
    const pct = progress.total > 0 ? (progress.completed / progress.total) * 100 : 0;

    const targetSummary = s.checkPreset === "none" ? s.destURL.replace(/^https?:\/\//, "") : s.checkPreset === "custom" ? t("Custom panel") : t(PRESET_LABELS[s.checkPreset]);
    const advancedBits = [
        s.timeout > 0 && t("timeout {n} ms", { n: s.timeout }),
        s.retries > 0 && t("{n} retries", { n: s.retries }),
        s.prescan && t("prescan"),
        s.maxPassed > 0 && t("stop at {n} passed", { n: s.maxPassed }),
        s.saveToDB && t("save to DB"),
        s.insecureTLS && t("insecure TLS"),
    ].filter(Boolean).join(", ");

    return (
        <Panel
            title={t("Test configs")}
            description={t("Find which links work from this network, and how fast.")}
            actions={
                <ConfirmButton
                    title={t("Reset tester settings?")}
                    description={t("All HTTP tester options go back to their defaults. Your pasted links stay.")}
                    confirmLabel={t("Reset")}
                    onConfirm={reset}
                    variant="ghost"
                    size="icon-sm"
                    disabled={busy}
                    aria-label={t("Reset tester settings")}
                >
                    <RotateCcw aria-hidden />
                </ConfirmButton>
            }
            bodyClassName="space-y-5"
        >
            <fieldset disabled={busy} className="space-y-5">
                {hasSubscriptions && (
                    <Field id="http-source" label={t("Configs to test")}>
                        <Select value={p.source} onValueChange={(v) => p.setSource(v as LinkSource)}>
                            <SelectTrigger id="http-source"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="links">{t("Pasted links")}</SelectItem>
                                <SelectItem value="subscription">{t("One subscription")}</SelectItem>
                                <SelectItem value="db">{t("All enabled subscriptions")}</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                )}
                {p.source === "links" && (
                    <LinkInput id="http-links" label={t("Share links")} value={p.links} onChange={p.setLinks} disabled={busy} tooLarge={p.linksTooLarge}
                        placeholder={"vless://…\nvmess://…\ntrojan://…\nhysteria2://…\ntg://proxy?…"} />
                )}
                {p.source === "subscription" && (
                    <Field id="http-sub" label={t("Subscription")} hint={subs.length === 0 ? t("No subscriptions yet. Add one on the Subscriptions page.") : undefined}>
                        <Select value={p.subscriptionId ? String(p.subscriptionId) : ""} onValueChange={(v) => p.setSubscriptionId(Number(v))}>
                            <SelectTrigger id="http-sub"><SelectValue placeholder={t("Choose a subscription")} /></SelectTrigger>
                            <SelectContent>
                                {subs.map((sub) => (
                                    <SelectItem key={sub.id} value={String(sub.id)}>
                                        {(sub.remark || sub.url.replace(/^https?:\/\//, "").slice(0, 40))} ({formatCount(sub.configCount)})
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </Field>
                )}

                {p.source !== "links" && (
                    <div className="grid grid-cols-2 gap-3">
                        <Field id="http-dbproto" label={t("Only this protocol")}>
                            <Select value={s.dbProtocol || "all"} onValueChange={(v) => update({ dbProtocol: v === "all" ? "" : v })}>
                                <SelectTrigger id="http-dbproto"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="all">{t("All protocols")}</SelectItem>
                                    {(info?.protocols?.map((x) => x.scheme) ?? ["vless", "vmess", "trojan", "ss", "hysteria2", "wireguard", "socks", "mtproto"]).map((pr) => <SelectItem key={pr} value={pr}>{pr}</SelectItem>)}
                                </SelectContent>
                            </Select>
                        </Field>
                        <Field id="http-dblimit" label={t("At most")} hint={t("0 = all configs")}>
                            <InputNumber id="http-dblimit" label={t("Config limit")} min={0} max={1_000_000} step={100} value={s.dbLimit} onChange={set("dbLimit")} />
                        </Field>
                    </div>
                )}

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                    <Field id="http-threads" label={t("Threads")}>
                        <InputNumber id="http-threads" label={t("Threads")} min={1} max={maxThreads} value={s.threadCount} onChange={set("threadCount")} />
                    </Field>
                    <Field id="http-maxdelay" label={t("Max delay (ms)")}>
                        <InputNumber id="http-maxdelay" label={t("Max delay")} min={100} max={65535} step={500} value={s.maxDelay} onChange={set("maxDelay")} />
                    </Field>
                    <Field id="http-core" label={t("Core")} className="col-span-2 sm:col-span-1">
                        <Select value={s.coreType} onValueChange={(v) => update({ coreType: v as HttpTesterSettings["coreType"] })}>
                            <SelectTrigger id="http-core"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="auto">{t("Automatic")}</SelectItem>
                                <SelectItem value="xray">Xray</SelectItem>
                                <SelectItem value="singbox">sing-box</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                </div>

                <div className="space-y-3">
                    <CheckRow id="http-speed" label={t("Measure download and upload speed")} hint={t("Slower: each passing config transfers data.")}>
                        <Checkbox id="http-speed" checked={s.speedtest} onCheckedChange={(c) => update({ speedtest: Boolean(c) })} />
                    </CheckRow>
                    {s.speedtest && (
                        <div className="grid grid-cols-2 gap-3 ps-6">
                            <Field id="http-speed-kb" label={t("Transfer (KB)")}>
                                <InputNumber id="http-speed-kb" label={t("Transfer size")} min={100} max={1_000_000} step={1000} value={s.speedtestAmount} onChange={set("speedtestAmount")} />
                            </Field>
                            <Field id="http-speed-to" label={t("Speed timeout (s)")} hint={t("0 = automatic")}>
                                <InputNumber id="http-speed-to" label={t("Speed timeout")} min={0} max={600} value={s.speedtestTimeout} onChange={set("speedtestTimeout")} />
                            </Field>
                            <Field id="http-speed-url" label={t("Speed test server (optional)")} hint={t("Empty = speed.cloudflare.com. A URL with a path is used as a plain download.")} className="col-span-2">
                                <Input id="http-speed-url" value={s.speedtestURL} onChange={(e) => update({ speedtestURL: e.target.value })} placeholder="https://speed.cloudflare.com" dir="ltr" className="font-mono text-xs md:text-xs" inputMode="url" />
                            </Field>
                        </div>
                    )}
                    <CheckRow id="http-ipinfo" label={t("Look up exit IP and country")}>
                        <Checkbox id="http-ipinfo" checked={s.doIPInfo} onCheckedChange={(c) => update({ doIPInfo: Boolean(c) })} />
                    </CheckRow>
                </div>

                <Collapsible title={t("Test target")} summary={targetSummary}>
                    <Field id="http-preset" label={t("Check")} hint={s.checkPreset === "none" ? t("One URL decides pass or fail.") : t("Several sites are probed; the pass threshold decides.")}>
                        <Select value={s.checkPreset} onValueChange={(v) => update({ checkPreset: v as CheckPreset })}>
                            <SelectTrigger id="http-preset"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="none">{t("Single URL")}</SelectItem>
                                {Object.entries(PRESET_LABELS).map(([k, label]) => <SelectItem key={k} value={k}>{t(label)}</SelectItem>)}
                                <SelectItem value="custom">{t("Custom panel")}</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                    {s.checkPreset === "none" && (
                        <div className="grid grid-cols-[1fr_6rem] gap-3">
                            <Field id="http-url" label={t("URL")}>
                                <Input id="http-url" value={s.destURL} onChange={(e) => update({ destURL: e.target.value })} dir="ltr" className="font-mono text-xs md:text-xs" inputMode="url" />
                            </Field>
                            <Field id="http-method" label={t("Method")}>
                                <Select value={s.httpMethod} onValueChange={(v) => update({ httpMethod: v as "GET" | "POST" })}>
                                    <SelectTrigger id="http-method"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="GET">GET</SelectItem>
                                        <SelectItem value="POST">POST</SelectItem>
                                    </SelectContent>
                                </Select>
                            </Field>
                        </div>
                    )}
                    {s.checkPreset === "custom" && (
                        <Field id="http-endpoints" label={t("Endpoints")} hint={t("One per line: URL, then optional method and expected status, e.g. https://www.gstatic.com/generate_204 GET 204")}>
                            <Textarea id="http-endpoints" rows={4} value={s.customEndpoints} onChange={(e) => update({ customEndpoints: e.target.value })} dir="ltr" className="font-mono text-xs md:text-xs" spellCheck={false} />
                        </Field>
                    )}
                    {s.checkPreset !== "none" && (
                        <Field id="http-threshold" label={t("Pass threshold (%)")} hint={t("Share of endpoints that must answer. 0 = all of them.")}>
                            <InputNumber id="http-threshold" label={t("Pass threshold")} min={0} max={100} step={10} value={Math.round(s.successThreshold * 100)} onChange={(v) => update({ successThreshold: v / 100 })} />
                        </Field>
                    )}
                </Collapsible>

                <Collapsible title={t("Advanced")} summary={advancedBits || t("Defaults")}>
                    <div className="grid grid-cols-2 gap-3">
                        <Field id="http-timeout" label={t("Timeout (ms)")} hint={t("0 = max delay")}>
                            <InputNumber id="http-timeout" label={t("Timeout")} min={0} max={65535} step={500} value={s.timeout} onChange={set("timeout")} />
                        </Field>
                        <Field id="http-retries" label={t("Retries")}>
                            <InputNumber id="http-retries" label={t("Retries")} min={0} max={10} value={s.retries} onChange={set("retries")} />
                        </Field>
                        <Field id="http-maxpassed" label={t("Stop after N passed")} hint={t("0 = test everything")}>
                            <InputNumber id="http-maxpassed" label={t("Stop after passed")} min={0} max={100000} value={s.maxPassed} onChange={set("maxPassed")} />
                        </Field>
                        <Field id="http-samples" label={t("Telegram probe samples")} hint={t("MTProto links: latency samples per proxy")}>
                            <InputNumber id="http-samples" label={t("Probe samples")} min={1} max={32} value={s.probeSamples} onChange={set("probeSamples")} />
                        </Field>
                    </div>
                    <div className="space-y-3">
                        <CheckRow id="http-prescan" label={t("TCP prescan")} hint={t("Drop unreachable servers quickly before the full test.")}>
                            <Checkbox id="http-prescan" checked={s.prescan} onCheckedChange={(c) => update({ prescan: Boolean(c) })} />
                        </CheckRow>
                        {s.prescan && (
                            <Field id="http-prescan-to" label={t("Prescan timeout (ms)")} hint={t("0 = 2000")} className="ps-6">
                                <InputNumber id="http-prescan-to" label={t("Prescan timeout")} min={0} max={30000} step={250} value={s.prescanTimeout} onChange={set("prescanTimeout")} />
                            </Field>
                        )}
                        <CheckRow id="http-dedup" label={t("Skip duplicate servers")} hint={t("Links that differ only in remark or parameter order are tested once.")}>
                            <Checkbox id="http-dedup" checked={s.dedup} onCheckedChange={(c) => update({ dedup: Boolean(c) })} />
                        </CheckRow>
                        <CheckRow id="http-savedb" label={t("Save results to the database")} hint={t("Makes this run appear in History.")}>
                            <Checkbox id="http-savedb" checked={s.saveToDB} onCheckedChange={(c) => update({ saveToDB: Boolean(c) })} />
                        </CheckRow>
                        <CheckRow id="http-nodiag" label={t("Skip failure diagnostics")} hint={t("Faster, but failed configs only get a guessed cause instead of a direct DNS/TCP/TLS check.")}>
                            <Checkbox id="http-nodiag" checked={s.noDiagnose} onCheckedChange={(c) => update({ noDiagnose: Boolean(c) })} />
                        </CheckRow>
                        {!s.noDiagnose && (
                            <Field id="http-resolver" label={t("Resolver for diagnostics (optional)")} hint={t("Compared with the system DNS to spot poisoning, e.g. https://1.1.1.1/dns-query or udp://8.8.8.8")}>
                                <Input id="http-resolver" value={s.resolver} onChange={(e) => update({ resolver: e.target.value })} placeholder="https://1.1.1.1/dns-query" dir="ltr" className="font-mono text-xs md:text-xs" inputMode="url" />
                            </Field>
                        )}
                        <CheckRow id="http-insecure" label={t("Allow insecure TLS")} hint={t("Accept self-signed or mismatched certificates.")}>
                            <Checkbox id="http-insecure" checked={s.insecureTLS} onCheckedChange={(c) => update({ insecureTLS: Boolean(c) })} />
                        </CheckRow>
                    </div>
                </Collapsible>

                <FragmentFields idPrefix="http" value={s.fragment} onChange={(fragment) => update({ fragment })} disabled={busy} core={s.coreType} />
            </fieldset>

            <div className="space-y-3">
                <div className="flex gap-2">
                    {status === "idle" ? (
                        <Button className="flex-1" onClick={p.onRun}><Play aria-hidden />{t("Run test")}</Button>
                    ) : (
                        <Button className="flex-1" disabled>
                            <Loader2 className="animate-spin" aria-hidden />
                            {status === "starting" ? t("Starting…") : status === "stopping" ? t("Stopping…") : t("Testing…")}
                        </Button>
                    )}
                    <Button variant="stop" onClick={p.onStop} disabled={status !== "running" && status !== "starting"}>
                        <Square aria-hidden />{t("Stop")}
                    </Button>
                </div>
                {(status === "running" || status === "stopping") && (
                    <div className="space-y-1.5" aria-live="polite">
                        <div className="flex justify-between text-xs text-muted-foreground">
                            <span>{phase && phase.phase !== "testing" ? (phase.message || t("Preparing: {phase}", { phase: phase.phase })) : t("Testing")}</span>
                            <span className="num">{progress.total > 0 ? `${formatCount(progress.completed)} / ${formatCount(progress.total)}` : ""}</span>
                        </div>
                        <Progress value={pct} aria-label={t("Test progress")} />
                    </div>
                )}
            </div>
        </Panel>
    );
}
