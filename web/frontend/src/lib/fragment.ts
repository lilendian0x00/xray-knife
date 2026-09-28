import type { FragmentNoise, FragmentOptions, FragmentRange, FragmentSettings } from "@/types/settings"

export const defaultFragment: FragmentSettings = {
    enabled: false,
    packetsMode: "tlshello",
    customPackets: "1-3",
    length: { min: 100, max: 200 },
    interval: { min: 10, max: 20 },
    noises: [],
}

export function rangeText(r: FragmentRange): string {
    return r.min === r.max ? String(r.min) : `${r.min}-${r.max}`
}

export function parseRange(s: string): FragmentRange | null {
    const m = /^\s*(\d+)\s*(?:-\s*(\d+)\s*)?$/.exec(s)
    if (!m) return null
    const min = Number(m[1])
    const max = m[2] === undefined ? min : Number(m[2])
    if (min > max) return null
    return { min, max }
}

function packetsOf(f: FragmentSettings): string {
    if (f.packetsMode === "custom") return f.customPackets.trim()
    return f.packetsMode
}

/** Mirrors fragment.Options.Validate in Go; returns the first problem or null. */
export function validateFragment(f: FragmentSettings): string | null {
    if (!f.enabled) return null
    const packets = packetsOf(f)
    if (packets !== "tlshello") {
        const r = parseRange(packets)
        if (!r) return 'Packets must be "tlshello" or a range like 1-3'
        if (r.min === 0) return "The packets range must start at 1"
    }
    if (f.length.min < 1) return "Fragment length must be at least 1 byte"
    if (f.length.min > f.length.max) return "Fragment length: minimum is above maximum"
    if (f.interval.min > f.interval.max) return "Fragment interval: minimum is above maximum"
    if (f.interval.max > 10_000) return "An interval above 10000 ms would stall every handshake"
    for (const [i, n] of f.noises.entries()) {
        if (!n.packet.trim()) return `Noise ${i + 1} has no packet`
        if (n.type === "rand" && !parseRange(n.packet)) return `Noise ${i + 1}: rand needs a length range like 10-20`
        if (n.delay.min > n.delay.max) return `Noise ${i + 1}: delay minimum is above maximum`
    }
    return null
}

/** Wire payload for the API, or undefined when fragmentation is off. */
export function fragmentPayload(f: FragmentSettings | undefined): FragmentOptions | undefined {
    if (!f || !f.enabled) return undefined
    const noises: FragmentNoise[] = f.noises.map((n) => ({ ...n, packet: n.packet.trim() }))
    return {
        packets: packetsOf(f),
        length: f.length,
        interval: f.interval,
        ...(noises.length > 0 ? { noises } : {}),
    }
}

/** Human-readable "tlshello,100-200,10-20" form, as the CLI takes it. */
export function fragmentSpec(f: FragmentSettings | undefined): string {
    if (!f || !f.enabled) return ""
    return `${packetsOf(f)},${rangeText(f.length)},${rangeText(f.interval)}`
}

/** Converts a wire fragment (e.g. a DPI finder profile) into form settings. */
export function settingsFromFragment(f: FragmentOptions | null | undefined): FragmentSettings {
    if (!f || !f.packets) return { ...defaultFragment, enabled: false };
    const packets = f.packets.toLowerCase();
    const mode: FragmentSettings["packetsMode"] = packets === "tlshello" ? "tlshello" : packets === "1-3" ? "1-3" : "custom";
    return {
        enabled: true,
        packetsMode: mode,
        customPackets: mode === "custom" ? packets : defaultFragment.customPackets,
        length: f.length ?? defaultFragment.length,
        interval: f.interval ?? { min: 0, max: 0 },
        noises: (f.noises ?? []).map((n) => ({ type: n.type, packet: n.packet, delay: n.delay ?? { min: 0, max: 0 } })),
    };
}

/** An xray freedom outbound carrying the fragment, for hand-written configs. */
export function xrayFragmentSnippet(f: FragmentOptions): string {
    const outbound = {
        tag: "fragment",
        protocol: "freedom",
        settings: {
            fragment: { packets: f.packets, length: rangeText(f.length), interval: rangeText(f.interval) },
            ...(f.noises?.length ? { noises: f.noises.map((n) => ({ type: n.type, packet: n.packet, delay: rangeText(n.delay) })) } : {}),
        },
    };
    return `${JSON.stringify(outbound, null, 2)}\n\n// In your proxy outbound:\n// "streamSettings": { "sockopt": { "dialerProxy": "fragment" } }`;
}
