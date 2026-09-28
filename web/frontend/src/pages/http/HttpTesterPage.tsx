import { useState } from "react";
import { toast } from "sonner";
import { SplitView } from "@/components/common/SplitView";
import { HttpSetup, type LinkSource } from "./HttpSetup";
import { HttpResults } from "./HttpResults";
import { usePersistentState } from "@/hooks/usePersistentState";
import { useSettingsStore } from "@/stores/settingsStore";
import { useRuntimeStore } from "@/stores/runtimeStore";
import { api, type HttpTestSource } from "@/services/api";
import { analyzeLinks } from "@/lib/links";
import { validateFragment } from "@/lib/fragment";
import { toastStartError, waitUntilIdle } from "@/lib/runControl";
import { errorMessage, formatCount } from "@/lib/utils";
import { useT } from "@/i18n";

export default function HttpTesterPage() {
    const t = useT();
    const [links, setLinks, { tooLarge }] = usePersistentState("httptest-configs-input", "");
    const [source, setSource] = usePersistentState<LinkSource>("httptest-source", "links");
    const [subscriptionId, setSubscriptionId] = usePersistentState<number | null>("httptest-sub", null);
    const status = useRuntimeStore((s) => s.httpStatus);
    const count = useRuntimeStore((s) => s.httpResults.length);
    const [runKey, setRunKey] = useState(0);

    const start = async (src: HttpTestSource, clear: boolean) => {
        const settings = useSettingsStore.getState().httpSettings;
        const fragErr = validateFragment(settings.fragment);
        if (fragErr) { toast.error(t("Fix the fragment settings first"), { description: fragErr }); return; }
        const rt = useRuntimeStore.getState();
        if (clear) rt.clearHttpResults();
        rt.setHttpStatus("starting");
        setRunKey((k) => k + 1);
        try {
            await api.startHttpTest(settings, src);
            // SSE moves us to "running"; don't wait for it to unlock the Stop button.
            if (useRuntimeStore.getState().httpStatus === "starting") useRuntimeStore.getState().setHttpStatus("running");
        } catch (err) {
            useRuntimeStore.getState().setHttpStatus("idle", errorMessage(err));
            toastStartError(err, t("HTTP test"));
        }
    };

    const run = () => {
        if (source === "links") {
            const a = analyzeLinks(links);
            if (a.links.length === 0) {
                toast.error(t("Nothing to test"), { description: a.invalid.length ? t("None of the {n} lines is a share link.", { n: a.invalid.length }) : t("Paste at least one share link.") });
                return;
            }
            if (a.duplicates > 0) toast.info(t("Skipping {n} duplicate lines", { n: formatCount(a.duplicates) }));
            void start({ links: a.links }, true);
        } else {
            const { dbProtocol, dbLimit } = useSettingsStore.getState().httpSettings;
            const filter = { ...(dbProtocol ? { protocol: dbProtocol } : {}), ...(dbLimit > 0 ? { limit: dbLimit } : {}) };
            if (source === "subscription") {
                if (!subscriptionId) { toast.error(t("Choose a subscription to test")); return; }
                void start({ subscriptionId, ...filter }, true);
            } else {
                void start({ fromDB: true, ...filter }, true);
            }
        }
    };

    const stop = async () => {
        const rt = useRuntimeStore.getState();
        rt.setHttpStatus("stopping");
        try {
            await api.stopHttpTest();
        } catch (err) {
            // 409 = it already ended; anything else we still resolve by polling.
            void err;
        }
        void waitUntilIdle(
            async () => (await api.httpTestStatus()).status,
            (st) => useRuntimeStore.getState().setHttpStatus(st),
            () => useRuntimeStore.getState().httpStatus === "stopping",
        );
    };

    const clear = async () => {
        try {
            await api.clearHttpTestHistory();
            useRuntimeStore.getState().clearHttpResults();
            toast.success(t("Results cleared"));
        } catch (err) {
            toast.error(t("Could not clear results"), { description: errorMessage(err) });
        }
    };

    return (
        <SplitView
            resultsSignal={runKey}
            resultsLabel={count > 0 ? formatCount(count) : undefined}
            setup={
                <HttpSetup
                    links={links} setLinks={setLinks} linksTooLarge={tooLarge}
                    source={source} setSource={setSource}
                    subscriptionId={subscriptionId} setSubscriptionId={setSubscriptionId}
                    onRun={run} onStop={stop}
                />
            }
            results={<HttpResults onRetest={(l) => status === "idle" && void start({ links: l }, false)} onClear={clear} />}
        />
    );
}
