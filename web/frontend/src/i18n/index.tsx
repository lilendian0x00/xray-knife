/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { fa } from "./fa";

// gettext-style: the English text is the key, other languages map it.
// Missing translations fall back to English, so strings can be wrapped
// incrementally. `{name}` placeholders are filled from `vars`.

export type Lang = "en" | "fa";

const DICTS: Record<Lang, Record<string, string>> = { en: {}, fa };
const RTL = new Set<Lang>(["fa"]);
const KEY = "xray-knife-lang";

type Vars = Record<string, string | number>;
export type T = (text: string, vars?: Vars) => string;

function interpolate(s: string, vars?: Vars) {
    if (!vars) return s;
    return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

function initialLang(): Lang {
    try {
        const saved = localStorage.getItem(KEY);
        if (saved === "en" || saved === "fa") return saved;
    } catch {
        // ignore
    }
    return navigator.language?.toLowerCase().startsWith("fa") ? "fa" : "en";
}

interface I18nState {
    lang: Lang;
    dir: "ltr" | "rtl";
    setLang: (l: Lang) => void;
    t: T;
}

const I18nContext = createContext<I18nState>({
    lang: "en",
    dir: "ltr",
    setLang: () => {},
    t: (s, v) => interpolate(s, v),
});

export function I18nProvider({ children }: { children: React.ReactNode }) {
    const [lang, setLangState] = useState<Lang>(initialLang);
    const dir = RTL.has(lang) ? "rtl" : "ltr";

    useEffect(() => {
        document.documentElement.lang = lang;
        document.documentElement.dir = dir;
    }, [lang, dir]);

    const setLang = useCallback((l: Lang) => {
        try { localStorage.setItem(KEY, l); } catch { /* ignore */ }
        setLangState(l);
    }, []);

    const t = useCallback<T>((text, vars) => interpolate(DICTS[lang][text] ?? text, vars), [lang]);
    const value = useMemo(() => ({ lang, dir, setLang, t }), [lang, dir, setLang, t]) as I18nState;
    return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const useI18n = () => useContext(I18nContext);
export const useT = () => useContext(I18nContext).t;
