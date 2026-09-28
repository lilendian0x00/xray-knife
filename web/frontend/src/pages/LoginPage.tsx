import { useEffect, useRef, useState } from "react";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { api } from "@/services/api";
import { ApiError } from "@/lib/http";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { BrandMark } from "@/components/shell/BrandMark";
import { errorMessage } from "@/lib/utils";
import { useNow } from "@/hooks/useNow";
import { useT } from "@/i18n";
import { Rich } from "@/components/common/Rich";

export default function LoginPage() {
    const t = useT();
    const setToken = useAuthStore((s) => s.setToken);
    const expired = useAuthStore((s) => s.lastLogoutReason === "expired");
    const [username, setUsername] = useState(() => {
        try { return localStorage.getItem("xray-knife-last-user") || ""; } catch { return ""; }
    });
    const [password, setPassword] = useState("");
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [lockedUntil, setLockedUntil] = useState<number | null>(null);
    const now = useNow(1000, lockedUntil !== null);
    const pwRef = useRef<HTMLInputElement>(null);
    const lockLeft = lockedUntil ? Math.max(0, Math.ceil((lockedUntil - now) / 1000)) : 0;

    useEffect(() => {
        if (lockedUntil && lockLeft === 0) setLockedUntil(null);
    }, [lockLeft, lockedUntil]);

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (busy || lockLeft > 0) return;
        setBusy(true);
        setError(null);
        try {
            const res = await api.login(username.trim(), password);
            try { localStorage.setItem("xray-knife-last-user", username.trim()); } catch { /* ignore */ }
            setToken(res.token);
        } catch (err) {
            if (err instanceof ApiError && err.status === 429) {
                const body = err.body as { retryAfter?: number } | undefined;
                const secs = body?.retryAfter ?? 30;
                setLockedUntil(Date.now() + secs * 1000);
                setError(t("Too many attempts. Wait a moment before trying again."));
            } else if (err instanceof ApiError && err.status === 401) {
                setError(t("Wrong username or password."));
                setPassword("");
                pwRef.current?.focus();
            } else {
                setError(errorMessage(err, t("Login failed")));
            }
        } finally {
            setBusy(false);
        }
    };

    return (
        <main className="grid min-h-dvh place-items-center bg-background p-4">
            <div className="w-full max-w-sm">
                <div className="mb-6 flex items-center gap-3">
                    <BrandMark className="size-9" />
                    <div>
                        <h1 className="text-lg font-semibold leading-6">xray-knife</h1>
                        <p className="text-sm text-muted-foreground">{t("Log in to the control panel")}</p>
                    </div>
                </div>
                <form onSubmit={submit} className="space-y-4 rounded-lg border bg-card p-5" noValidate>
                    {expired && !error && (
                        <p className="rounded-md bg-semi/10 px-3 py-2 text-sm text-semi" role="status">{t("Your session expired. Log in again to continue.")}</p>
                    )}
                    <div className="space-y-1.5">
                        <Label htmlFor="username">{t("Username")}</Label>
                        <Input id="username" autoComplete="username" autoFocus={!username} value={username} onChange={(e) => setUsername(e.target.value)} required dir="ltr" />
                    </div>
                    <div className="space-y-1.5">
                        <Label htmlFor="password">{t("Password")}</Label>
                        <div className="relative">
                            <Input
                                ref={pwRef}
                                id="password"
                                type={show ? "text" : "password"}
                                autoComplete="current-password"
                                autoFocus={!!username}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="pe-10"
                                aria-invalid={!!error}
                                aria-describedby={error ? "login-error" : undefined}
                                dir="ltr"
                                required
                            />
                            <Button type="button" variant="ghost" size="icon-sm" className="absolute end-1 top-1/2 -translate-y-1/2"
                                onClick={() => setShow((s) => !s)} aria-label={show ? t("Hide password") : t("Show password")} aria-pressed={show}>
                                {show ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
                            </Button>
                        </div>
                    </div>
                    {error && <p id="login-error" role="alert" className="text-sm text-fail">{error}{lockLeft > 0 && ` (${lockLeft} s)`}</p>}
                    <Button type="submit" className="w-full" disabled={busy || lockLeft > 0 || !username.trim() || !password}>
                        {busy && <Loader2 className="animate-spin" aria-hidden />}
                        {busy ? t("Logging in…") : t("Log in")}
                    </Button>
                </form>
                <p className="mt-4 text-xs text-muted-foreground"><Rich text={t("The username and password were printed when `xray-knife webui` started, or set with its --auth flags.")} /></p>
            </div>
        </main>
    );
}
