import { create } from 'zustand';
import { jwtExpiry } from '@/lib/utils';

const TOKEN_KEY = 'xray-knife-token';
const LEGACY_KEY = 'xray-knife-app-storage';

function readStoredToken(): string | null {
    try {
        const t = localStorage.getItem(TOKEN_KEY);
        if (t) return t;
        // Older builds kept the token inside the settings blob.
        const legacy = localStorage.getItem(LEGACY_KEY);
        if (legacy) {
            const parsed = JSON.parse(legacy) as { state?: { token?: string | null } };
            return parsed?.state?.token ?? null;
        }
    } catch {
        // storage unavailable (private mode) — treat as logged out
    }
    return null;
}

function tokenValid(token: string | null): boolean {
    if (!token) return false;
    const exp = jwtExpiry(token);
    return exp === null || exp * 1000 > Date.now();
}

export type LogoutReason = 'manual' | 'expired';

interface AuthState {
    token: string | null;
    /** null until /auth/check answered. */
    authRequired: boolean | null;
    /** false when /auth/check could not reach the server. */
    serverReachable: boolean;
    lastLogoutReason: LogoutReason | null;
    setToken: (token: string) => void;
    setAuthRequired: (required: boolean) => void;
    setServerReachable: (ok: boolean) => void;
    logout: (reason?: LogoutReason) => void;
}

const initial = readStoredToken();

export const useAuthStore = create<AuthState>()((set) => ({
    token: tokenValid(initial) ? initial : null,
    authRequired: null,
    serverReachable: true,
    lastLogoutReason: null,
    setToken: (token) => {
        try { localStorage.setItem(TOKEN_KEY, token); } catch { /* ignore */ }
        set({ token, lastLogoutReason: null });
    },
    setAuthRequired: (required) => set({ authRequired: required, serverReachable: true }),
    setServerReachable: (ok) => set({ serverReachable: ok }),
    logout: (reason = 'manual') => {
        try { localStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
        set({ token: null, lastLogoutReason: reason });
    },
}));

export const selectIsAuthenticated = (s: AuthState) => s.authRequired === false || tokenValid(s.token);

export function tokenExpiresAt(token: string | null): number | null {
    if (!token) return null;
    const exp = jwtExpiry(token);
    return exp === null ? null : exp * 1000;
}
