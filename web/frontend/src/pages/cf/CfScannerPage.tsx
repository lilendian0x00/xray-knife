import { useState } from "react";
import { toast } from "sonner";
import { SplitView } from "@/components/common/SplitView";
import { CfSetup } from "./CfSetup";
import { CfResults } from "./CfResults";
import { usePersistentState } from "@/hooks/usePersistentState";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { api } from "@/services/api";
import { analyzeSubnets } from "@/lib/links";
import { validateFragment } from "@/lib/fragment";
import { toastStartError, waitUntilIdle } from "@/lib/runControl";
import { errorMessage, formatCount } from "@/lib/utils";
import { normalizeTaskStatus } from "@/services/events";
import { useT } from "@/i18n";

export default function CfScannerPage() {
    const t = useT();
    const [subnets, setSubnets, { tooLarge }] = usePersistentState("cfscanner-subnets-input", "");
    const count = useRuntimeStore((s) => s.scanResults.length);
    const canResume = useRuntimeStore((s) => s.scanResults.length > 0 || s.scanFailed > 0);
    const [runKey, setRunKey] = useState(0);

    const start = async (resume: boolean) => {
        const a = analyzeSubnets(subnets);
        if (a.subnets.length === 0) {
            toast.error(t("Nothing to scan"), { description: a.invalid.length ? t("None of the lines is an IP or CIDR range.") : t("Paste ranges or load the Cloudflare list first.") });
            return;
        }
        if (a.invalid.length > 0) toast.warning(t("Skipping {n} lines that aren't IPs or ranges", { n: a.invalid.length }));
        const settings = useSettingsStore.getState().cfScannerSettings;
        if (settings.advancedOptions.configLink.trim()) {
            const fragErr = validateFragment(settings.fragment);
            if (fragErr) { toast.error(t("Fix the fragment settings first"), { description: fragErr }); return; }
        }
        const rt = useRuntimeStore.getState();
        rt.setScanStatus("starting");
        setRunKey((k) => k + 1);
        try {
            if (!resume) {
                await api.clearCfHistory().catch(() => undefined);
                useRuntimeStore.getState().clearScanResults();
            }
            await api.startCfScan(settings, a.subnets, resume);
            if (useRuntimeStore.getState().scanStatus === "starting") useRuntimeStore.getState().setScanStatus("running");
        } catch (err) {
            useRuntimeStore.getState().setScanStatus("idle", errorMessage(err));
            toastStartError(err, t("Scan"));
        }
    };

    const stop = async () => {
        useRuntimeStore.getState().setScanStatus("stopping");
        try { await api.stopCfScan(); } catch { /* resolved by polling */ }
        void waitUntilIdle(
            async () => {
                const s = await api.cfStatus();
                return s.status ?? (s.is_scanning ? "running" : "idle");
            },
            (st) => useRuntimeStore.getState().setScanStatus(normalizeTaskStatus(st === "idle" ? "idle" : st).status),
            () => useRuntimeStore.getState().scanStatus === "stopping",
        );
    };

    const clear = async () => {
        try {
            await api.clearCfHistory();
            useRuntimeStore.getState().clearScanResults();
            toast.success(t("Scan results cleared"));
        } catch (err) {
            toast.error(t("Could not clear results"), { description: errorMessage(err) });
        }
    };

    return (
        <SplitView
            resultsSignal={runKey}
            resultsLabel={count > 0 ? formatCount(count) : undefined}
            setup={<CfSetup subnets={subnets} setSubnets={setSubnets} subnetsTooLarge={tooLarge} onStart={start} onStop={stop} canResume={canResume} />}
            results={<CfResults onClear={clear} />}
        />
    );
}
