import { useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { Play, Square, Loader2, RotateCcw, CloudDownload, ChevronDown, RefreshCcw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { InputNumber } from "@/components/ui/input-number";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Panel } from "@/components/common/Panel";
import { Field, CheckRow } from "@/components/common/Field";
import { Collapsible } from "@/components/common/Collapsible";
import { LinkInput } from "@/components/common/LinkInput";
import { FragmentFields } from "@/components/common/FragmentFields";
import { ConfirmButton } from "@/components/common/ConfirmButton";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useServerStore } from "@/stores/serverStore";
import { api } from "@/services/api";
import type { CfScannerSettings } from "@/types/settings";
import { errorMessage, formatCount } from "@/lib/utils";
import { useT } from "@/i18n";

const CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443, 80, 8080, 8880, 2052, 2082, 2086, 2095];

interface CfSetupProps {
    subnets: string;
    setSubnets: (v: string) => void;
    subnetsTooLarge: boolean;
    onStart: (resume: boolean) => void;
    onStop: () => void;
    canResume: boolean;
}

export function CfSetup(p: CfSetupProps) {
    const t = useT();
    const { s, update, reset } = useSettingsStore(useShallow((st) => ({ s: st.cfScannerSettings, update: st.updateCfScannerSettings, reset: st.resetCfScannerSettings })));
    const { status, progress, succeeded, failed } = useRuntimeStore(useShallow((st) => ({
        status: st.scanStatus, progress: st.scanProgress, succeeded: st.scanResults.length, failed: st.scanFailed,
    })));
    const maxThreads = useServerStore((st) => st.info?.limits?.maxScannerThreads ?? 4096);
    const [loadingRanges, setLoadingRanges] = useState(false);
    const busy = status !== "idle";
    const pct = progress.total > 0 ? (progress.completed / progress.total) * 100 : 0;
    const customPort = !CF_PORTS.includes(s.port);
    const configMode = s.advancedOptions.configLink.trim() !== "";
    const setSpeed = (patch: Partial<CfScannerSettings["speedtestOptions"]>) => update({ speedtestOptions: { ...s.speedtestOptions, ...patch } });
    const setAdv = (patch: Partial<CfScannerSettings["advancedOptions"]>) => update({ advancedOptions: { ...s.advancedOptions, ...patch } });

    const loadRanges = async (v6: boolean) => {
        setLoadingRanges(true);
        try {
            const r = await api.cfRanges(v6);
            const list = v6 ? r.ranges : (r.v4 ?? r.ranges.filter((x) => !x.includes(":")));
            p.setSubnets(list.join("\n"));
            toast.success(t("Loaded {n} Cloudflare ranges", { n: list.length }), {
                description: r.source === "fallback" ? t("cloudflare.com was unreachable, so the built-in list was used.") : undefined,
            });
        } catch (err) {
            toast.error(t("Could not load the ranges"), { description: errorMessage(err) });
        } finally {
            setLoadingRanges(false);
        }
    };

    const wideV6 = p.subnets.includes(":") && /:[0-9a-f]*\/(\d|[1-9]\d|10\d|11[01])\b/i.test(p.subnets) && s.samplePerSubnet === 0;
    const advSummary = [
        s.samplePerSubnet > 0 && t("{n} per range", { n: s.samplePerSubnet }),
        s.advancedOptions.shuffleIPs && t("shuffled IPs"),
        s.advancedOptions.shuffleSubnets && t("shuffled ranges"),
        s.saveToDB && t("save to DB"),
        configMode && t("through a config"),
    ].filter(Boolean).join(", ");

    return (
        <Panel
            title={t("Scan Cloudflare IPs")}
            description={t("Find edge IPs that answer quickly from this network.")}
            actions={
                <ConfirmButton title={t("Reset scanner settings?")} description={t("All scanner options go back to their defaults. Your ranges stay.")} confirmLabel={t("Reset")}
                    onConfirm={reset} variant="ghost" size="icon-sm" disabled={busy} aria-label={t("Reset scanner settings")}>
                    <RotateCcw aria-hidden />
                </ConfirmButton>
            }
            bodyClassName="space-y-5"
        >
            <fieldset disabled={busy} className="space-y-5">
                <LinkInput
                    id="cf-subnets" kind="subnets" label={t("IP ranges")} value={p.subnets} onChange={p.setSubnets} disabled={busy} tooLarge={p.subnetsTooLarge}
                    placeholder={"104.16.0.0/13\n172.64.0.0/13\n162.159.192.1"}
                    action={
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button type="button" variant="ghost" size="sm" className="h-7 px-2 text-xs" disabled={busy || loadingRanges}>
                                    {loadingRanges ? <Loader2 className="animate-spin" aria-hidden /> : <CloudDownload aria-hidden />}{t("Cloudflare ranges")}<ChevronDown aria-hidden className="opacity-60" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                                <DropdownMenuItem onSelect={() => loadRanges(false)}>{t("IPv4 ranges")}</DropdownMenuItem>
                                <DropdownMenuItem onSelect={() => loadRanges(true)}>{t("IPv4 and IPv6 (IPv6 is sampled or rejected)")}</DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    }
                />
                <div className="grid grid-cols-2 gap-3">
                    <Field id="cf-threads" label={t("Threads")}>
                        <InputNumber id="cf-threads" label={t("Threads")} min={1} max={maxThreads} value={s.threadCount} onChange={(v) => update({ threadCount: v })} />
                    </Field>
                    <Field id="cf-timeout" label={t("Timeout (ms)")}>
                        <InputNumber id="cf-timeout" label={t("Timeout")} min={100} max={60000} step={250} value={s.timeout} onChange={(v) => update({ timeout: v })} />
                    </Field>
                    <Field id="cf-retry" label={t("Retries")}>
                        <InputNumber id="cf-retry" label={t("Retries")} min={0} max={10} value={s.retry} onChange={(v) => update({ retry: v })} />
                    </Field>
                    <Field id="cf-port" label={t("Port")} hint={s.port === 443 ? undefined : t("Try alternate ports when 443 is filtered")}>
                        <Select value={customPort ? "custom" : String(s.port)} onValueChange={(v) => update({ port: v === "custom" ? 8444 : Number(v) })}>
                            <SelectTrigger id="cf-port"><SelectValue /></SelectTrigger>
                            <SelectContent>
                                {CF_PORTS.map((port) => <SelectItem key={port} value={String(port)}>{port}{port === 443 ? ` (${t("default")})` : [80, 8080, 8880, 2052, 2082, 2086, 2095].includes(port) ? ` (${t("no TLS")})` : ""}</SelectItem>)}
                                <SelectItem value="custom">{t("Other…")}</SelectItem>
                            </SelectContent>
                        </Select>
                    </Field>
                    {customPort && (
                        <Field id="cf-port-custom" label={t("Custom port")}>
                            <InputNumber id="cf-port-custom" label={t("Custom port")} min={1} max={65535} value={s.port} onChange={(v) => update({ port: v })} />
                        </Field>
                    )}
                </div>

                <div className="space-y-3">
                    <CheckRow id="cf-speed" label={t("Speed-test the best IPs")} hint={t("Downloads and uploads through the fastest responders after the scan.")}>
                        <Checkbox id="cf-speed" checked={s.doSpeedtest} onCheckedChange={(c) => update({ doSpeedtest: Boolean(c) })} />
                    </CheckRow>
                    {s.doSpeedtest && (
                        <div className="grid grid-cols-2 gap-3 ps-6 sm:grid-cols-3">
                            <Field id="cf-top" label={t("Best N")}><InputNumber id="cf-top" label={t("Best N")} min={1} max={1000} value={s.speedtestOptions.top} onChange={(v) => setSpeed({ top: v })} /></Field>
                            <Field id="cf-conc" label={t("In parallel")}><InputNumber id="cf-conc" label={t("In parallel")} min={1} max={64} value={s.speedtestOptions.concurrency} onChange={(v) => setSpeed({ concurrency: v })} /></Field>
                            <Field id="cf-sto" label={t("Timeout (s)")}><InputNumber id="cf-sto" label={t("Speed timeout")} min={5} max={600} value={s.speedtestOptions.timeout} onChange={(v) => setSpeed({ timeout: v })} /></Field>
                            <Field id="cf-dl" label={t("Download (MB)")}><InputNumber id="cf-dl" label={t("Download size")} min={1} max={1000} value={s.speedtestOptions.downloadMB} onChange={(v) => setSpeed({ downloadMB: v })} /></Field>
                            <Field id="cf-ul" label={t("Upload (MB)")}><InputNumber id="cf-ul" label={t("Upload size")} min={0} max={1000} value={s.speedtestOptions.uploadMB} onChange={(v) => setSpeed({ uploadMB: v })} /></Field>
                            <Field id="cf-speed-url" label={t("Speed test server (optional)")} hint={t("Empty = speed.cloudflare.com")} className="col-span-2 sm:col-span-3">
                                <Input id="cf-speed-url" value={s.speedtestURL} onChange={(e) => update({ speedtestURL: e.target.value })} placeholder="https://speed.cloudflare.com" dir="ltr" className="font-mono text-xs md:text-xs" inputMode="url" />
                            </Field>
                        </div>
                    )}
                </div>

                <Collapsible title={t("Advanced")} summary={advSummary || t("Defaults")} defaultOpen={configMode || wideV6}>
                    <div className="grid grid-cols-2 gap-3">
                        <Field id="cf-sample" label={t("Sample per range")} hint={wideV6 ? t("Needed for large IPv6 ranges") : t("Random IPs per /24 (IPv4) or /48 (IPv6). 0 = every address.")}>
                            <InputNumber id="cf-sample" label={t("Sample per range")} min={0} max={256} value={s.samplePerSubnet} onChange={(v) => update({ samplePerSubnet: v })} />
                        </Field>
                        <Field id="cf-maxips" label={t("At most N IPs")} hint={t("0 = server default")}>
                            <InputNumber id="cf-maxips" label={t("Maximum IPs")} min={0} max={16_777_216} step={10000} value={s.maxIPs} onChange={(v) => update({ maxIPs: v })} />
                        </Field>
                    </div>
                    <div className="space-y-3">
                        <CheckRow id="cf-shuf-ip" label={t("Shuffle IPs inside each range")}>
                            <Checkbox id="cf-shuf-ip" checked={s.advancedOptions.shuffleIPs} onCheckedChange={(c) => setAdv({ shuffleIPs: Boolean(c) })} />
                        </CheckRow>
                        <CheckRow id="cf-shuf-net" label={t("Shuffle the order of ranges")}>
                            <Checkbox id="cf-shuf-net" checked={s.advancedOptions.shuffleSubnets} onCheckedChange={(c) => setAdv({ shuffleSubnets: Boolean(c) })} />
                        </CheckRow>
                        <CheckRow id="cf-savedb" label={t("Save results to the database")} hint={t("Resume can then pick up after a restart.")}>
                            <Checkbox id="cf-savedb" checked={s.saveToDB} onCheckedChange={(c) => update({ saveToDB: Boolean(c) })} />
                        </CheckRow>
                    </div>
                    <Field id="cf-config" label={t("Scan through a config (optional)")} hint={t("Each IP is tested as the address of this link, so only IPs that carry your real traffic pass. Also lets you copy ready configs from the results.")}>
                        <Input id="cf-config" placeholder="vless://…@example.com:443?security=tls&type=ws…" value={s.advancedOptions.configLink} onChange={(e) => setAdv({ configLink: e.target.value })} dir="ltr" className="font-mono text-xs md:text-xs" />
                    </Field>
                    {configMode && (
                        <CheckRow id="cf-insecure" label={t("Allow insecure TLS for the config")}>
                            <Checkbox id="cf-insecure" checked={s.advancedOptions.insecureTLS} onCheckedChange={(c) => setAdv({ insecureTLS: Boolean(c) })} />
                        </CheckRow>
                    )}
                </Collapsible>

                {configMode && <FragmentFields idPrefix="cf" value={s.fragment} onChange={(fragment) => update({ fragment })} disabled={busy} />}
            </fieldset>

            <div className="space-y-3">
                <div className="flex flex-wrap gap-2">
                    {status === "idle" ? (
                        <>
                            <Button className="flex-1" onClick={() => p.onStart(false)}><Play aria-hidden />{t("New scan")}</Button>
                            <Button variant="secondary" onClick={() => p.onStart(true)} disabled={!p.canResume} title={t("Skip IPs that were already scanned")}><RefreshCcw aria-hidden />{t("Resume")}</Button>
                        </>
                    ) : (
                        <Button className="flex-1" disabled>
                            <Loader2 className="animate-spin" aria-hidden />
                            {status === "starting" ? t("Starting…") : status === "stopping" ? t("Stopping…") : t("Scanning…")}
                        </Button>
                    )}
                    <Button variant="stop" onClick={p.onStop} disabled={status !== "running" && status !== "starting"}><Square aria-hidden />{t("Stop")}</Button>
                </div>
                {(status === "running" || status === "stopping") && (
                    <div className="space-y-1.5" aria-live="polite">
                        <div className="flex justify-between gap-2 text-xs text-muted-foreground">
                            <span className="num">{t("{ok} answered, {bad} no answer", { ok: formatCount(progress.succeeded ?? succeeded), bad: formatCount(progress.failed ?? failed) })}</span>
                            <span className="num">{progress.total > 0 ? `${formatCount(progress.completed)} / ${formatCount(progress.total)}` : ""}</span>
                        </div>
                        <Progress value={pct} aria-label={t("Scan progress")} />
                    </div>
                )}
            </div>
        </Panel>
    );
}
