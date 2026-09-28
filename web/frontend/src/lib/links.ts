// Parsing of pasted link lists and subnet lists, shared by every form.

export interface LinkAnalysis {
    /** Unique, trimmed entries in first-seen order. */
    links: string[]
    duplicates: number
    invalid: string[]
    total: number
}

const SCHEME_RE = /^([a-z][a-z0-9+.-]*):\/\/\S+$/i
const KNOWN_SCHEMES = new Set([
    "vmess", "vless", "trojan", "ss", "ssr", "socks", "socks4", "socks5", "socks5h", "http", "https",
    "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "wg", "anytls", "ssh", "tg", "shadowtls", "naive+https",
])

export function isLikelyLink(line: string): boolean {
    const m = SCHEME_RE.exec(line)
    return !!m && KNOWN_SCHEMES.has(m[1].toLowerCase())
}

function splitLines(text: string): string[] {
    return text
        .replace(/^\uFEFF/, "")
        .split(/\r\n|\r|\n/)
        .map((l) => l.trim())
        .filter((l) => l !== "" && !l.startsWith("#") && !l.startsWith("//"))
}

export function analyzeLinks(text: string): LinkAnalysis {
    const lines = splitLines(text)
    const seen = new Set<string>()
    const links: string[] = []
    const invalid: string[] = []
    let duplicates = 0
    for (const line of lines) {
        if (!isLikelyLink(line)) {
            invalid.push(line)
            continue
        }
        if (seen.has(line)) {
            duplicates++
            continue
        }
        seen.add(line)
        links.push(line)
    }
    return { links, duplicates, invalid, total: lines.length }
}

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

function isIPv4(s: string) {
    return IPV4_RE.test(s)
}

function isIPv6(s: string) {
    if (!s.includes(":")) return false
    try {
        new URL(`http://[${s}]/`)
        return true
    } catch {
        return false
    }
}

export interface SubnetAnalysis {
    subnets: string[]
    duplicates: number
    invalid: string[]
    /** IPv6 ranges wider than /112 are huge; the backend samples or rejects them. */
    wideIPv6: string[]
    ipv4Addresses: number
}

export function analyzeSubnets(text: string): SubnetAnalysis {
    const lines = splitLines(text)
    const seen = new Set<string>()
    const subnets: string[] = []
    const invalid: string[] = []
    const wideIPv6: string[] = []
    let duplicates = 0
    let ipv4Addresses = 0
    for (const line of lines) {
        const [addr, prefixStr, extra] = line.split("/")
        if (extra !== undefined) {
            invalid.push(line)
            continue
        }
        const v4 = isIPv4(addr)
        const v6 = !v4 && isIPv6(addr)
        if (!v4 && !v6) {
            invalid.push(line)
            continue
        }
        const max = v4 ? 32 : 128
        const prefix = prefixStr === undefined ? max : Number(prefixStr)
        if (!Number.isInteger(prefix) || prefix < 0 || prefix > max || (prefixStr !== undefined && prefixStr.trim() === "")) {
            invalid.push(line)
            continue
        }
        const key = `${addr.toLowerCase()}/${prefix}`
        if (seen.has(key)) {
            duplicates++
            continue
        }
        seen.add(key)
        subnets.push(line)
        if (v4) ipv4Addresses += 2 ** (32 - prefix)
        else if (prefix < 112) wideIPv6.push(line)
    }
    return { subnets, duplicates, invalid, wideIPv6, ipv4Addresses }
}

/** Proxy protocol shown in tables, from the link's scheme. */
export function linkProtocol(link: string): string {
    const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(link)
    if (!m) return "?"
    const s = m[1].toLowerCase()
    if (s === "hy2") return "hysteria2"
    if (s === "tg" || link.startsWith("https://t.me/proxy")) return "mtproto"
    return s
}

/** Remark (the #fragment) of a share link, decoded when possible. */
export function linkRemark(link: string): string {
    const i = link.lastIndexOf("#")
    if (i < 0 || link.startsWith("vmess://")) return ""
    const raw = link.slice(i + 1)
    try {
        return decodeURIComponent(raw)
    } catch {
        return raw
    }
}

function b64decode(s: string): string {
    const norm = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = norm.length % 4 ? "=".repeat(4 - (norm.length % 4)) : "";
    const bin = atob(norm + pad);
    return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

function b64encode(s: string): string {
    const bytes = new TextEncoder().encode(s);
    let bin = "";
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin);
}

/**
 * Returns the share link with its server address replaced by `ip` (for
 * turning clean Cloudflare IPs into ready configs). SNI/Host parameters are
 * kept, so CDN-fronted configs keep working. Returns null for link kinds
 * whose address can't be swapped safely.
 */
export function replaceAddress(link: string, ip: string): string | null {
    const host = ip.includes(":") ? `[${ip}]` : ip;
    if (link.startsWith("vmess://")) {
        try {
            const body = link.slice(8).split("#")[0];
            const obj = JSON.parse(b64decode(body)) as Record<string, unknown>;
            if (!obj.host && typeof obj.add === "string" && !/^[\d.:[\]]+$/.test(obj.add)) obj.host = obj.add;
            if (!obj.sni && typeof obj.add === "string" && obj.tls === "tls" && !/^[\d.:[\]]+$/.test(obj.add)) obj.sni = obj.add;
            obj.add = ip;
            obj.ps = `${String(obj.ps ?? "")} ${ip}`.trim();
            return `vmess://${b64encode(JSON.stringify(obj))}`;
        } catch {
            return null;
        }
    }
    const m = /^(vless|trojan|ss|hysteria2|hy2):\/\/([^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)(:\d+)?([^#]*)(#.*)?$/i.exec(link);
    if (!m) return null;
    const [, scheme, userinfo = "", oldHost, port = "", rest = "", frag = ""] = m;
    let query = rest;
    // Keep the old hostname as SNI/Host when the link relied on it implicitly.
    if (!/^[\d.]+$/.test(oldHost) && !oldHost.startsWith("[")) {
        const params = new URLSearchParams(query.includes("?") ? query.slice(query.indexOf("?") + 1) : "");
        const path = query.includes("?") ? query.slice(0, query.indexOf("?")) : query;
        let changed = false;
        if (!params.has("sni") && (params.get("security") === "tls" || scheme === "trojan")) { params.set("sni", oldHost); changed = true; }
        if (!params.has("host") && (params.get("type") === "ws" || params.get("type") === "httpupgrade" || params.get("type") === "xhttp")) { params.set("host", oldHost); changed = true; }
        if (changed) query = `${path}?${params.toString()}`;
    }
    const remark = frag ? `${frag}${encodeURIComponent(` ${ip}`)}` : `#${encodeURIComponent(ip)}`;
    return `${scheme}://${userinfo}${host}${port}${query}${remark}`;
}
