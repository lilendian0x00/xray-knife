import { useEffect, useRef, useState } from "react";

// Persists a value in localStorage. Writes are debounced (typing into a
// multi-megabyte textarea must not serialise on every keystroke) and values
// above `maxBytes` are kept in memory only, so the quota is never blown.
export function usePersistentState<T>(
    key: string,
    defaultValue: T,
    { debounceMs = 400, maxBytes = 1_500_000 }: { debounceMs?: number; maxBytes?: number } = {},
): [T, React.Dispatch<React.SetStateAction<T>>, { tooLarge: boolean }] {
    const [value, setValue] = useState<T>(() => {
        try {
            const stored = window.localStorage.getItem(key);
            if (stored !== null) return JSON.parse(stored) as T;
        } catch {
            // unreadable → default
        }
        return defaultValue;
    });
    const [tooLarge, setTooLarge] = useState(false);
    const first = useRef(true);

    useEffect(() => {
        if (first.current) {
            first.current = false;
            return;
        }
        const id = window.setTimeout(() => {
            try {
                const json = JSON.stringify(value);
                if (json.length > maxBytes) {
                    window.localStorage.removeItem(key);
                    setTooLarge(true);
                    return;
                }
                window.localStorage.setItem(key, json);
                setTooLarge(false);
            } catch {
                setTooLarge(true);
            }
        }, debounceMs);
        return () => window.clearTimeout(id);
    }, [key, value, debounceMs, maxBytes]);

    return [value, setValue, { tooLarge }];
}
