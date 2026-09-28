import { lazy, Suspense, useEffect } from "react";
import { Loader2 } from "lucide-react";
import { AppShell } from "@/components/shell/AppShell";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";
import { useHashRoute, type Page } from "@/hooks/useHashRoute";
import { events } from "@/services/events";
import { api } from "@/services/api";
import { useAuthStore } from "@/stores/authStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { useServerStore } from "@/stores/serverStore";
import { useLogStore } from "@/stores/logStore";
import { useT } from "@/i18n";

const ProxyPage = lazy(() => import("./proxy/ProxyPage"));
const HttpTesterPage = lazy(() => import("./http/HttpTesterPage"));
const CfScannerPage = lazy(() => import("./cf/CfScannerPage"));
const DpiPage = lazy(() => import("./dpi/DpiPage"));
const SubscriptionsPage = lazy(() => import("./subscriptions/SubscriptionsPage"));
const HistoryPage = lazy(() => import("./history/HistoryPage"));
const SettingsPage = lazy(() => import("./settings/SettingsPage"));

const TITLES: Record<Page, string> = {
    proxy: "Proxy", http: "HTTP tester", cf: "CF scanner", dpi: "DPI finder", subscriptions: "Subscriptions", history: "History", settings: "Settings",
};

function PageFallback() {
    return (
        <div className="flex h-48 items-center justify-center text-sm text-muted-foreground" role="status">
            <Loader2 className="me-2 size-4 animate-spin" aria-hidden />
        </div>
    );
}

export default function Dashboard() {
    const t = useT();
    const [page, navigate] = useHashRoute();
    const authRequired = useAuthStore((s) => s.authRequired);

    useEffect(() => {
        events.start();
        void useServerStore.getState().load();
        return () => events.stop();
    }, []);

    useEffect(() => {
        document.title = `${t(TITLES[page])} | xray-knife`;
    }, [page, t]);

    const logout = () => {
        events.stop();
        api.logout().catch(() => {});
        useAuthStore.getState().logout("manual");
        useRuntimeStore.getState().reset();
        useLogStore.getState().clear();
    };

    return (
        <AppShell page={page} navigate={navigate} onLogout={authRequired ? logout : undefined}>
            <ErrorBoundary area={t(TITLES[page])} resetKey={page}>
                <Suspense fallback={<PageFallback />}>
                    {page === "proxy" && <ProxyPage />}
                    {page === "http" && <HttpTesterPage />}
                    {page === "cf" && <CfScannerPage />}
                    {page === "dpi" && <DpiPage navigate={navigate} />}
                    {page === "subscriptions" && <SubscriptionsPage navigate={navigate} />}
                    {page === "history" && <HistoryPage navigate={navigate} />}
                    {page === "settings" && <SettingsPage onLogout={authRequired ? logout : undefined} />}
                </Suspense>
            </ErrorBoundary>
        </AppShell>
    );
}
