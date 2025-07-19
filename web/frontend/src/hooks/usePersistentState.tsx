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
                const parsedValue = JSON.parse(storedValue);

                // FIX: Only apply object-merging logic if the default value is a non-array object.
                // This prevents strings, numbers, and other primitives from being incorrectly treated as objects.
                if (typeof defaultValue === 'object' && defaultValue !== null && !Array.isArray(defaultValue)) {
                    return merge(parsedValue as Partial<T>);
                }
                
                // For primitives (like strings) and arrays, return the parsed value directly.
                return parsedValue as T;
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