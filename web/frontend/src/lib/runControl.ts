import { toast } from "sonner";
import { ApiError } from "@/lib/http";
import { events, normalizeTaskStatus } from "@/services/events";
import { errorMessage } from "@/lib/utils";
import type { TaskStatus } from "@/stores/runtimeStore";

/**
 * After a stop request, poll the status endpoint until the service reports
 * idle, so a lost final event can never leave the UI stuck on "Stopping…".
 */
export async function waitUntilIdle(
    getStatus: () => Promise<string | undefined>,
    setStatus: (s: TaskStatus) => void,
    isStill: () => boolean,
    timeoutMs = 20_000,
) {
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
        await new Promise((r) => window.setTimeout(r, 1000));
        if (!isStill()) return; // an event already moved us on
        try {
            const { status } = normalizeTaskStatus(await getStatus());
            if (status === "idle") {
                setStatus("idle");
                return;
            }
        } catch {
            // keep polling
        }
    }
    // Give up waiting but resync so the screen matches the server.
    void events.sync();
}

/** Toast text for a failed start; 409 means another run is active. */
export function startErrorText(err: unknown, what: string): string {
    if (err instanceof ApiError && err.status === 409) {
        void events.sync();
        return `${what} is already running or still stopping`;
    }
    return errorMessage(err);
}

export function toastStartError(err: unknown, what: string) {
    toast.error(`Could not start ${what.toLowerCase()}`, { description: startErrorText(err, what) });
}
