import type { ExportFormat } from "@/services/api";

export const EXPORT_FORMATS: { value: ExportFormat; label: string; hint: string }[] = [
    { value: "base64", label: "Base64 subscription", hint: "v2rayNG, Hiddify, NekoBox, Streisand" },
    { value: "plain", label: "Plain links", hint: "One share link per line" },
    { value: "clash", label: "Clash / mihomo YAML", hint: "Clash Verge, ClashX, mihomo" },
    { value: "singbox", label: "sing-box JSON", hint: "sing-box, SFA, SFI" },
    { value: "xray", label: "Xray JSON", hint: "xray-core configs" },
];
