// Opt-in browser notifications for long runs that finish while the tab is hidden.

const KEY = "xray-knife-notify";

export function notificationsSupported(): boolean {
    return typeof window !== "undefined" && "Notification" in window && window.isSecureContext;
}

export function notificationsEnabled(): boolean {
    if (!notificationsSupported()) return false;
    try {
        return localStorage.getItem(KEY) === "1" && Notification.permission === "granted";
    } catch {
        return false;
    }
}

export async function setNotificationsEnabled(on: boolean): Promise<boolean> {
    if (!notificationsSupported()) return false;
    if (on && Notification.permission !== "granted") {
        const p = await Notification.requestPermission();
        if (p !== "granted") on = false;
    }
    try {
        localStorage.setItem(KEY, on ? "1" : "0");
    } catch {
        // ignore
    }
    return on;
}

export function notifyDone(title: string, body: string) {
    if (!notificationsEnabled() || document.visibilityState === "visible") return;
    try {
        new Notification(title, { body, icon: "/icon.svg", tag: title });
    } catch {
        // Some mobile browsers only allow notifications from a service worker.
    }
}
