import { useState } from "react";
import { toast } from "sonner";
import { SplitView } from "@/components/common/SplitView";
import { ProxySetup, type ProxySource } from "./ProxySetup";
import { ProxyStatusPanel } from "./ProxyStatusPanel";
import { usePersistentState } from "@/hooks/usePersistentState";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { api } from "@/services/api";
import { ApiError } from "@/lib/http";
import { analyzeLinks } from "@/lib/links";
import { validateFragment } from "@/lib/fragment";
import { waitUntilIdle, toastStartError } from "@/lib/runControl";
import { errorMessage } from "@/lib/utils";
import { events } from "@/services/events";
import { useT } from "@/i18n";
import { useServerStore } from "@/stores/serverStore";

export default function ProxyPage() {
    const t = useT();
    const [links, setLinks, { tooLarge }] = usePersistentState("proxy-configs-input", "");
    const [source, setSource] = usePersistentState<ProxySource>("proxy-source", "links");
    const [portError, setPortError] = useState<string | null>(null);
    const [runKey, setRunKey] = useState(0);

    const start = async () => {
        const settings = useSettingsStore.getState().proxySettings;
        const port = Number(settings.listenPort);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            setPortError(t("Use a port between 1 and 65535"));
            return;
        }
        setPortError(null);
        let list: string[] = [];
        if (source === "links") {
            const a = analyzeLinks(links);
            if (a.links.length === 0 && !(settings.chain && settings.chainLinks.trim())) {
                toast.error(t("Add at least one share link"));
                return;
            }
            list = a.links;
        }
        if (settings.enableTls && settings.mode !== "system" && settings.inboundProtocol !== "socks" && (!settings.tlsCertPath.trim() || !settings.tlsKeyPath.trim())) {
            toast.error(t("TLS needs a certificate file and a key file"));
            return;
        }
        if ((settings.mode === "app" || settings.mode === "host-tun") && useServerStore.getState().info?.allowHostModes !== true) {
            toast.error(t("This server does not allow host modes"), { description: t("Restart it with --allow-host-modes, or pick another mode.") });
            return;
        }
        const fragErr = validateFragment(settings.fragment);
        if (fragErr) { toast.error(t("Fix the fragment settings first"), { description: fragErr }); return; }

        const rt = useRuntimeStore.getState();
        rt.setProxyStatus("starting");
        setRunKey((k) => k + 1);
        try {
            await api.startProxy(settings, list, source === "db");
            if (useRuntimeStore.getState().proxyStatus === "starting") useRuntimeStore.getState().setProxyStatus("running");
            void events.sync();
        } catch (err) {
            useRuntimeStore.getState().setProxyStatus("stopped", errorMessage(err));
            toastStartError(err, t("Proxy"));
        }
    };

    const stop = async () => {
        useRuntimeStore.getState().setProxyStatus("stopping");
        try {
            await api.stopProxy();
            useRuntimeStore.getState().setProxyStatus("stopped", null);
        } catch (err) {
            if (err instanceof ApiError && (err.status === 409 || err.status === 404)) {
                useRuntimeStore.getState().setProxyStatus("stopped", null);
                return;
            }
            toast.error(t("Stopping is taking longer than expected"), { description: errorMessage(err) });
            void waitUntilIdle(
                async () => ((await api.proxyStatus()).status === "stopped" ? "idle" : "running"),
                () => useRuntimeStore.getState().setProxyStatus("stopped", null),
                () => useRuntimeStore.getState().proxyStatus === "stopping",
            );
        }
    };

    const rotate = async () => {
        try {
            await api.rotateProxy();
            toast.success(t("Looking for a new outbound"));
        } catch (err) {
            toast.error(t("Could not rotate"), { description: errorMessage(err) });
        }
    };

    return (
        <SplitView
            resultsSignal={runKey}
            setupWidth="lg:grid-cols-[minmax(22rem,28rem)_minmax(0,1fr)]"
            setup={<ProxySetup links={links} setLinks={setLinks} linksTooLarge={tooLarge} source={source} setSource={setSource} onStart={start} onStop={stop} onRotate={rotate} portError={portError} />}
            results={<ProxyStatusPanel />}
        />
    );
}
