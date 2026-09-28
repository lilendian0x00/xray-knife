import { useEffect, useState } from "react";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import { cn } from "@/lib/utils";
import { useT } from "@/i18n";

interface SplitViewProps {
    setup: React.ReactNode;
    results: React.ReactNode;
    resultsLabel?: React.ReactNode;
    /** Bump this (e.g. on each run start) to switch small screens to the results pane. */
    resultsSignal?: number;
    setupWidth?: string;
}

/**
 * Setup pane + results pane side by side on wide screens; a Setup/Results
 * switch on narrow ones so results never sit a long scroll below the form.
 */
export function SplitView({ setup, results, resultsLabel, resultsSignal = 0, setupWidth = "lg:grid-cols-[minmax(21rem,27rem)_minmax(0,1fr)]" }: SplitViewProps) {
    const t = useT();
    const wide = useMediaQuery("(min-width: 1024px)");
    const [tab, setTab] = useState<"setup" | "results">("setup");

    useEffect(() => {
        if (resultsSignal > 0) setTab("results");
    }, [resultsSignal]);

    if (wide) {
        return <div className={cn("grid items-start gap-4 lg:gap-5", setupWidth)}>{setup}{results}</div>;
    }
    return (
        <div className="space-y-3">
            <div role="tablist" aria-label={t("View")} className="grid grid-cols-2 gap-1 rounded-lg border bg-card p-1">
                {(["setup", "results"] as const).map((id) => (
                    <button
                        key={id}
                        role="tab"
                        type="button"
                        aria-selected={tab === id}
                        onClick={() => setTab(id)}
                        className={cn("rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-2", tab === id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent")}
                    >
                        {id === "setup" ? t("Setup") : <>{t("Results")}{resultsLabel != null && <span className="num ms-1.5 opacity-80">{resultsLabel}</span>}</>}
                    </button>
                ))}
            </div>
            <div role="tabpanel">{tab === "setup" ? setup : results}</div>
        </div>
    );
}
