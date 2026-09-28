import { useEffect, useState } from "react";

/** Re-renders every `intervalMs` while `active`, returning Date.now(). */
export function useNow(intervalMs = 1000, active = true): number {
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        if (!active) return;
        const id = window.setInterval(() => setNow(Date.now()), intervalMs);
        return () => window.clearInterval(id);
    }, [intervalMs, active]);
    return now;
}
