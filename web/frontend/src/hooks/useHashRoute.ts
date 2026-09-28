import { useCallback, useSyncExternalStore } from "react";

export const PAGES = ["proxy", "http", "cf", "dpi", "subscriptions", "history", "settings"] as const;
export type Page = (typeof PAGES)[number];

const LEGACY: Record<string, Page> = { "http-tester": "http", "cf-scanner": "cf" };

function parse(hash: string): Page {
    const id = hash.replace(/^#\/?/, "").split(/[/?]/)[0];
    if ((PAGES as readonly string[]).includes(id)) return id as Page;
    return LEGACY[id] ?? "proxy";
}

function subscribe(cb: () => void) {
    window.addEventListener("hashchange", cb);
    return () => window.removeEventListener("hashchange", cb);
}

/** The current page lives in the URL hash so reload and back/forward work. */
export function useHashRoute(): [Page, (p: Page) => void] {
    const page = useSyncExternalStore(subscribe, () => parse(window.location.hash), () => "proxy" as Page);
    const navigate = useCallback((p: Page) => {
        if (parse(window.location.hash) !== p) window.location.hash = `/${p}`;
    }, []);
    return [page, navigate];
}
