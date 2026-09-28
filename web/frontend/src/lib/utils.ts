import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// --- Formatting ---

export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return "—"
  if (ms >= 10_000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.round(ms)} ms`
}

export function formatMbps(v: number | null | undefined): string {
  if (!v || !Number.isFinite(v) || v <= 0) return "—"
  return v >= 100 ? `${v.toFixed(0)} Mbps` : `${v.toFixed(2)} Mbps`
}

/** Formats a duration in seconds as h:mm:ss (or m:ss under an hour). */
export function formatCountdown(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const pad = (n: number) => String(n).padStart(2, "0")
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat().format(n)
}

export function errorMessage(err: unknown, fallback = "Unknown error"): string {
  if (err instanceof Error && err.message) return err.message
  if (typeof err === "string" && err) return err
  return fallback
}

// --- Downloads ---

function triggerDownload(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  // Safari needs the URL alive until the download has started.
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

type CsvCell = string | number | boolean | null | undefined

function csvCell(c: CsvCell): string {
  if (c === null || c === undefined) return ""
  if (typeof c === "number") return Number.isFinite(c) ? String(c) : ""
  if (typeof c === "boolean") return c ? "true" : "false"
  return `"${c.replace(/"/g, '""')}"`
}

/** Writes a CSV with a UTF-8 BOM (so Excel reads remarks correctly) and raw numbers. */
export function downloadCSV(filename: string, headers: string[], rows: CsvCell[][]) {
  const csv = [headers.map(csvCell).join(","), ...rows.map((r) => r.map(csvCell).join(","))].join("\r\n")
  triggerDownload(filename, new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }))
}

export function downloadJSON(filename: string, data: unknown) {
  triggerDownload(filename, new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }))
}

export function downloadText(filename: string, lines: string[]) {
  triggerDownload(filename, new Blob([lines.join("\n") + "\n"], { type: "text/plain;charset=utf-8" }))
}

// --- Clipboard ---

/**
 * Copies text, falling back to a hidden textarea + execCommand when the async
 * Clipboard API is missing (plain-http LAN addresses are not secure contexts).
 */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch {
      // fall through to the legacy path
    }
  }
  const ta = document.createElement("textarea")
  ta.value = text
  ta.setAttribute("readonly", "")
  ta.style.position = "fixed"
  ta.style.insetInlineStart = "-9999px"
  ta.style.top = "0"
  document.body.appendChild(ta)
  const selection = document.getSelection()
  const previous = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null
  ta.select()
  let ok = false
  try {
    ok = document.execCommand("copy")
  } finally {
    ta.remove()
    if (previous && selection) {
      selection.removeAllRanges()
      selection.addRange(previous)
    }
  }
  if (!ok) throw new Error("Copy is blocked by the browser")
}

/** Reads a JWT's exp claim (seconds) without verifying it. */
export function jwtExpiry(token: string): number | null {
  try {
    const part = token.split(".")[1]
    if (!part) return null
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"))
    const payload = JSON.parse(json) as { exp?: number }
    return typeof payload.exp === "number" ? payload.exp : null
  } catch {
    return null
  }
}

/** "3 min ago" style text, via Intl.RelativeTimeFormat in the page language. */
export function formatRelative(iso: string | null | undefined, lang = document.documentElement.lang || "en"): string {
  if (!iso) return ""
  const then = new Date(iso).getTime()
  if (!Number.isFinite(then)) return ""
  const diff = (then - Date.now()) / 1000
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" })
  const abs = Math.abs(diff)
  if (abs < 60) return rtf.format(Math.round(diff), "second")
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute")
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour")
  return rtf.format(Math.round(diff / 86400), "day")
}
