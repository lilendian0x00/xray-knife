import { useState, useEffect } from "react";

// A custom hook to persist state in localStorage
export function usePersistentState<T>(
    key: string,
    defaultValue: T,
    merge: (loaded: Partial<T>) => T = (loaded) => ({ ...defaultValue, ...loaded })
): [T, React.Dispatch<React.SetStateAction<T>>] {
    const [value, setValue] = useState<T>(() => {
        try {
            const storedValue = window.localStorage.getItem(key);
            if (storedValue) {
                // Merge the loaded state with defaults to ensure all keys are present
                return merge(JSON.parse(storedValue) as Partial<T>);
            }
        } catch (error) {
            console.error(`Error reading localStorage key “${key}”:`, error);
        }
        return defaultValue;
    });

    useEffect(() => {
        try {
            window.localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.error(`Error setting localStorage key “${key}”:`, error);
        }
    }, [key, value]);

    return [value, setValue];
}