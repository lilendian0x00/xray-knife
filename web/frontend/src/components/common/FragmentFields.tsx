import { Plus, Trash2, Scissors } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Field, CheckRow } from "./Field";
import { RangeInput } from "./RangeInput";
import { Collapsible } from "./Collapsible";
import { fragmentSpec, validateFragment } from "@/lib/fragment";
import type { FragmentSettings, NoiseType } from "@/types/settings";
import { useT } from "@/i18n";

interface FragmentFieldsProps {
    idPrefix: string;
    value: FragmentSettings;
    onChange: (f: FragmentSettings) => void;
    disabled?: boolean;
    /** The selected core; sing-box only honours on/off and tlshello. */
    core?: string;
    note?: React.ReactNode;
}

export function FragmentFields({ idPrefix, value, onChange, disabled, core, note }: FragmentFieldsProps) {
    const t = useT();
    const set = (patch: Partial<FragmentSettings>) => onChange({ ...value, ...patch });
    const error = validateFragment(value);
    const isSingbox = core === "singbox" || core === "sing-box";

    return (
        <Collapsible
            title={<span className="inline-flex items-center gap-2"><Scissors className="size-3.5 text-muted-foreground" aria-hidden />{t("TLS fragment")}</span>}
            summary={value.enabled ? fragmentSpec(value) : t("Off")}
            defaultOpen={value.enabled}
        >
            <CheckRow
                id={`${idPrefix}-frag-on`}
                label={t("Split the TLS handshake")}
                hint={t("Hides the SNI from DPI that only reads the first packet. Try it when configs fail with resets but work on other networks.")}
            >
                <Checkbox id={`${idPrefix}-frag-on`} checked={value.enabled} onCheckedChange={(c) => set({ enabled: Boolean(c) })} disabled={disabled} />
            </CheckRow>

            {value.enabled && (
                <div className="space-y-4">
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <Field id={`${idPrefix}-frag-packets`} label={t("Packets")} hint={value.packetsMode === "tlshello" ? t("Only the ClientHello record") : t("The first TCP writes of the stream")}>
                            <Select value={value.packetsMode} onValueChange={(v) => set({ packetsMode: v as FragmentSettings["packetsMode"] })} disabled={disabled}>
                                <SelectTrigger id={`${idPrefix}-frag-packets`}><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="tlshello">tlshello</SelectItem>
                                    <SelectItem value="1-3">1-3</SelectItem>
                                    <SelectItem value="custom">{t("Custom range")}</SelectItem>
                                </SelectContent>
                            </Select>
                        </Field>
                        {value.packetsMode === "custom" && (
                            <Field id={`${idPrefix}-frag-custom`} label={t("Packet range")} hint={t("For example 1-5")}>
                                <Input id={`${idPrefix}-frag-custom`} value={value.customPackets} onChange={(e) => set({ customPackets: e.target.value })} disabled={disabled} dir="ltr" className="font-mono" />
                            </Field>
                        )}
                    </div>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <RangeInput id={`${idPrefix}-frag-len`} label={t("Length")} unit={t("bytes")} value={value.length} min={1} max={16384} onChange={(length) => set({ length })} disabled={disabled} />
                        <RangeInput id={`${idPrefix}-frag-int`} label={t("Interval")} unit="ms" value={value.interval} min={0} max={10000} onChange={(interval) => set({ interval })} disabled={disabled} />
                    </div>

                    <div className="space-y-2">
                        <div className="flex items-center justify-between">
                            <p className="text-[13px] font-medium">{t("UDP noise")} <span className="font-normal text-muted-foreground">({t("xray only")})</span></p>
                            <Button type="button" variant="ghost" size="sm" className="h-7 text-xs" disabled={disabled}
                                onClick={() => set({ noises: [...value.noises, { type: "rand", packet: "10-20", delay: { min: 10, max: 16 } }] })}>
                                <Plus aria-hidden />{t("Add noise")}
                            </Button>
                        </div>
                        {value.noises.length === 0 && <p className="text-xs text-muted-foreground">{t("No noise packets. Noise helps QUIC and WireGuard through filters that fingerprint the first datagram.")}</p>}
                        {value.noises.map((n, i) => (
                            <div key={i} className="grid grid-cols-[6.5rem_1fr_auto] items-end gap-2 rounded-md border p-2">
                                <Field id={`${idPrefix}-noise-${i}-type`} label={t("Type")}>
                                    <Select value={n.type} onValueChange={(v) => set({ noises: value.noises.map((x, j) => j === i ? { ...x, type: v as NoiseType } : x) })} disabled={disabled}>
                                        <SelectTrigger id={`${idPrefix}-noise-${i}-type`}><SelectValue /></SelectTrigger>
                                        <SelectContent>
                                            {(["rand", "str", "base64", "hex"] as NoiseType[]).map((ty) => <SelectItem key={ty} value={ty}>{ty}</SelectItem>)}
                                        </SelectContent>
                                    </Select>
                                </Field>
                                <Field id={`${idPrefix}-noise-${i}-packet`} label={n.type === "rand" ? t("Length range") : t("Payload")}>
                                    <Input id={`${idPrefix}-noise-${i}-packet`} value={n.packet} dir="ltr" className="font-mono" disabled={disabled}
                                        onChange={(e) => set({ noises: value.noises.map((x, j) => j === i ? { ...x, packet: e.target.value } : x) })} />
                                </Field>
                                <Button type="button" variant="ghost" size="icon" aria-label={t("Remove noise {n}", { n: i + 1 })} disabled={disabled}
                                    onClick={() => set({ noises: value.noises.filter((_, j) => j !== i) })}>
                                    <Trash2 aria-hidden />
                                </Button>
                                <div className="col-span-3">
                                    <RangeInput id={`${idPrefix}-noise-${i}-delay`} label={t("Delay")} unit="ms" value={n.delay} min={0} max={10000} disabled={disabled}
                                        onChange={(delay) => set({ noises: value.noises.map((x, j) => j === i ? { ...x, delay } : x) })} />
                                </div>
                            </div>
                        ))}
                    </div>

                    {isSingbox && (
                        <p className="rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">
                            {t("sing-box picks segment sizes itself: it uses fragmentation on/off (and record splitting for tlshello) and ignores length, interval and noise.")}
                        </p>
                    )}
                    {note}
                    {error && <p role="alert" className="text-xs text-fail">{error}</p>}
                </div>
            )}
        </Collapsible>
    );
}
