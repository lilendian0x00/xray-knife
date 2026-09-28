import type { HttpResult } from "@/types/dashboard";
import { linkProtocol, linkRemark } from "@/lib/links";

export const STATUS_ORDER: Record<string, number> = { passed: 0, "semi-passed": 1, failed: 2, timeout: 3, broken: 4, canceled: 5 };

export const isWorking = (r: HttpResult) => r.status === "passed" || r.status === "semi-passed";

export function resultProtocol(r: HttpResult): string {
    return r.protocol?.protocol || linkProtocol(r.link);
}

export function resultName(r: HttpResult): string {
    return r.protocol?.remark || linkRemark(r.link) || (r.protocol?.address ? `${r.protocol.address}:${r.protocol.port}` : "");
}

export function hasDelay(r: HttpResult) {
    return isWorking(r) && r.delay > 0;
}

export type SortField = "status" | "delay" | "download" | "upload" | "location" | "protocol" | "name";

export function compareResults(a: HttpResult, b: HttpResult, field: SortField, dir: 1 | -1): number {
    // Working configs always come first; the chosen sort applies within groups.
    const ga = isWorking(a) ? 0 : 1;
    const gb = isWorking(b) ? 0 : 1;
    if (ga !== gb) return ga - gb;
    switch (field) {
        case "status": return ((STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)) * dir;
        case "delay": {
            if (!hasDelay(a) || !hasDelay(b)) return (hasDelay(a) ? -1 : 0) + (hasDelay(b) ? 1 : 0);
            return (a.delay - b.delay) * dir;
        }
        case "download": return ((a.download || 0) - (b.download || 0)) * dir;
        case "upload": return ((a.upload || 0) - (b.upload || 0)) * dir;
        case "location": return (a.location || "").localeCompare(b.location || "") * dir;
        case "protocol": return resultProtocol(a).localeCompare(resultProtocol(b)) * dir;
        case "name": return resultName(a).localeCompare(resultName(b)) * dir;
    }
}

export function cleanLocation(loc: string | undefined): string {
    if (!loc || loc === "null" || loc === "N/A") return "";
    return loc;
}

export function cleanIp(ip: string | undefined): string {
    if (!ip || ip === "null" || ip === "N/A" || ip === "-") return "";
    return ip;
}

/** Flag emoji for a 2-letter country code (renders as letters where unsupported). */
export function flag(cc: string): string {
    if (!/^[A-Za-z]{2}$/.test(cc)) return "";
    const base = 0x1f1e6;
    return String.fromCodePoint(...cc.toUpperCase().split("").map((c) => base + c.charCodeAt(0) - 65));
}

export { FAILURE_KINDS, FAILURE_GROUPS, failureLabel } from "@/lib/failureKinds";
