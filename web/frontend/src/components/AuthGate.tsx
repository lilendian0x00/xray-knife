import { useCallback, useEffect } from "react";
import { toast } from "sonner";
import { Loader2, ServerCrash, RefreshCw } from "lucide-react";
import { useAuthStore, selectIsAuthenticated, tokenExpiresAt } from "@/stores/authStore";
import { configureHttp } from "@/lib/http";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { BrandMark } from "@/components/shell/BrandMark";
import LoginPage from "@/pages/LoginPage";
import { useT } from "@/i18n";
import { Rich } from "@/components/common/Rich";

// Route every 401 to the login screen, once.
configureHttp({
    getToken: () => useAuthStore.getState().token,
    onUnauthorized: () => {
        const s = useAuthStore.getState();
        if (s.token) {
            s.logout("expired");
        }
    },
});

function FullScreen({ children }: { children: React.ReactNode }) {
    return <div className="flex min-h-dvh items-center justify-center bg-background p-6">{children}</div>;
}

export function AuthGate({ children }: { children: React.ReactNode }) {
    const t = useT();
    const authRequired = useAuthStore((s) => s.authRequired);
    const reachable = useAuthStore((s) => s.serverReachable);
    const token = useAuthStore((s) => s.token);
    const reason = useAuthStore((s) => s.lastLogoutReason);
    const isAuthed = useAuthStore(selectIsAuthenticated);

    const check = useCallback(() => {
        useAuthStore.getState().setServerReachable(true);
        api.checkAuth()
            .then((r) => useAuthStore.getState().setAuthRequired(r.auth_required))
            .catch(() => useAuthStore.getState().setServerReachable(false));
    }, []);

    useEffect(() => {
        if (authRequired === null) check();
    }, [authRequired, check]);

    // Log out exactly when the token expires, instead of on the next failed call.
    useEffect(() => {
        const exp = tokenExpiresAt(token);
        if (!exp) return;
        const ms = exp - Date.now();
        if (ms <= 0) { useAuthStore.getState().logout("expired"); return; }
        const id = window.setTimeout(() => useAuthStore.getState().logout("expired"), Math.min(ms, 2 ** 31 - 1));
        return () => window.clearTimeout(id);
    }, [token]);

    useEffect(() => {
        if (reason === "expired") toast.warning(t("Your session expired. Log in again to continue."), { id: "session-expired" });
    }, [reason, t]);

    if (!reachable) {
        return (
            <FullScreen>
                <div className="max-w-sm space-y-4 text-center">
                    <ServerCrash className="mx-auto size-8 text-fail" aria-hidden />
                    <h1 className="text-lg font-semibold">{t("Can't reach the xray-knife server")}</h1>
                    <p className="text-sm text-muted-foreground"><Rich text={t("Check that `xray-knife webui` is still running and that this address is correct.")} /></p>
                    <Button onClick={check}><RefreshCw aria-hidden />{t("Try again")}</Button>
                </div>
            </FullScreen>
        );
    }
    if (authRequired === null) {
        return (
            <FullScreen>
                <div className="flex items-center gap-3 text-sm text-muted-foreground" role="status">
                    <BrandMark className="size-7" />
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                    {t("Connecting…")}
                </div>
            </FullScreen>
        );
    }
    if (authRequired && !isAuthed) return <LoginPage />;
    return <>{children}</>;
}
