// Small fetch wrapper: bearer auth, JSON in/out, a hard timeout on every
// request (so "Stopping…" can never hang forever) and typed errors.

export class ApiError extends Error {
    readonly status: number
    readonly body: unknown

    constructor(message: string, status: number, body?: unknown) {
        super(message)
        this.name = "ApiError"
        this.status = status
        this.body = body
    }

    /** True for "the server does not have this endpoint" (older backend). */
    get isMissing() {
        return this.status === 404 || this.status === 405 || this.status === 501
    }
}

export class TimeoutError extends Error {
    constructor(ms: number) {
        super(`The server did not answer within ${Math.round(ms / 1000)} s`)
        this.name = "TimeoutError"
    }
}

export class NetworkError extends Error {
    constructor() {
        super("Cannot reach the xray-knife server")
        this.name = "NetworkError"
    }
}

interface HttpHooks {
    getToken: () => string | null
    onUnauthorized: () => void
}

let hooks: HttpHooks = { getToken: () => null, onUnauthorized: () => {} }

export function configureHttp(h: HttpHooks) {
    hooks = h
}

export interface RequestOptions {
    body?: unknown
    /** Milliseconds; defaults to 15 s. */
    timeout?: number
    signal?: AbortSignal
    /** Skip the global 401 handler (e.g. the login call itself). */
    noAuthRedirect?: boolean
}

const DEFAULT_TIMEOUT = 15_000

export async function request<T>(method: string, url: string, opts: RequestOptions = {}): Promise<T> {
    const timeout = opts.timeout ?? DEFAULT_TIMEOUT
    const controller = new AbortController()
    const timer = window.setTimeout(() => controller.abort(new TimeoutError(timeout)), timeout)
    const onOuterAbort = () => controller.abort(opts.signal?.reason)
    opts.signal?.addEventListener("abort", onOuterAbort, { once: true })

    const headers: Record<string, string> = { Accept: "application/json" }
    const token = hooks.getToken()
    if (token) headers.Authorization = `Bearer ${token}`
    let body: BodyInit | undefined
    if (opts.body !== undefined) {
        headers["Content-Type"] = "application/json"
        body = JSON.stringify(opts.body)
    }

    let res: Response
    try {
        res = await fetch(url, { method, headers, body, signal: controller.signal, credentials: "same-origin" })
    } catch (err) {
        if (controller.signal.aborted) {
            const reason = controller.signal.reason
            throw reason instanceof Error ? reason : new TimeoutError(timeout)
        }
        void err
        throw new NetworkError()
    } finally {
        window.clearTimeout(timer)
        opts.signal?.removeEventListener("abort", onOuterAbort)
    }

    const text = await res.text()
    let data: unknown = undefined
    if (text) {
        try {
            data = JSON.parse(text)
        } catch {
            data = text
        }
    }

    if (!res.ok) {
        if (res.status === 401 && !opts.noAuthRedirect) hooks.onUnauthorized()
        const msg =
            (data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
                ? (data as { error: string }).error
                : typeof data === "string" && data.length < 300
                  ? data.trim()
                  : "") || `${res.status} ${res.statusText || "request failed"}`
        throw new ApiError(msg, res.status, data)
    }
    return data as T
}

export const http = {
    get: <T>(url: string, opts?: RequestOptions) => request<T>("GET", url, opts),
    post: <T>(url: string, body?: unknown, opts?: RequestOptions) => request<T>("POST", url, { ...opts, body }),
    put: <T>(url: string, body?: unknown, opts?: RequestOptions) => request<T>("PUT", url, { ...opts, body }),
    patch: <T>(url: string, body?: unknown, opts?: RequestOptions) => request<T>("PATCH", url, { ...opts, body }),
    del: <T>(url: string, opts?: RequestOptions) => request<T>("DELETE", url, opts),
}

export interface Download {
    blob: Blob
    filename: string
    headers: Headers
}

/**
 * GET a file with the bearer header (a plain <a href> can't carry it).
 * Errors are parsed like request(): JSON `{error}` bodies become ApiError.
 */
export async function download(url: string, opts: { timeout?: number; fallbackName?: string } = {}): Promise<Download> {
    const timeout = opts.timeout ?? 60_000
    const controller = new AbortController()
    const timer = window.setTimeout(() => controller.abort(new TimeoutError(timeout)), timeout)
    const headers: Record<string, string> = {}
    const token = hooks.getToken()
    if (token) headers.Authorization = `Bearer ${token}`
    let res: Response
    try {
        res = await fetch(url, { headers, signal: controller.signal, credentials: "same-origin" })
    } catch {
        window.clearTimeout(timer)
        if (controller.signal.aborted) throw new TimeoutError(timeout)
        throw new NetworkError()
    }
    try {
        if (!res.ok) {
            const text = await res.text()
            let data: unknown = text
            try { data = JSON.parse(text) } catch { /* plain text */ }
            if (res.status === 401) hooks.onUnauthorized()
            const msg = data && typeof data === "object" && "error" in data ? String((data as { error: unknown }).error) : text.slice(0, 300) || `${res.status}`
            throw new ApiError(msg, res.status, data)
        }
        const blob = await res.blob()
        const cd = res.headers.get("Content-Disposition") ?? ""
        const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd)
        const filename = m ? decodeURIComponent(m[1]) : opts.fallbackName ?? "download"
        return { blob, filename, headers: res.headers }
    } finally {
        window.clearTimeout(timer)
    }
}
