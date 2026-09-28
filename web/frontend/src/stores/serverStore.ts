import { create } from 'zustand';
import { api, type ServerInfo, CHECK_PRESETS, type EndpointCheck } from '@/services/api';
import { ApiError } from '@/lib/http';

// What the connected backend supports. Newer pages hide themselves when their
// endpoints are missing instead of failing on every click.
interface ServerStoreState {
    info: ServerInfo | null;
    /** null = unknown yet. */
    hasSubscriptions: boolean | null;
    hasHistory: boolean | null;
    loaded: boolean;
    load: () => Promise<void>;
    presets: () => Record<string, EndpointCheck[]>;
}

async function probe(fn: () => Promise<unknown>): Promise<boolean> {
    try {
        await fn();
        return true;
    } catch (err) {
        // A 5xx (e.g. DB unavailable) still means the feature exists.
        return err instanceof ApiError && !err.isMissing && err.status !== 401;
    }
}

export const useServerStore = create<ServerStoreState>()((set, get) => ({
    info: null,
    hasSubscriptions: null,
    hasHistory: null,
    loaded: false,
    load: async () => {
        const [info, subs, hist] = await Promise.all([
            api.info().catch(() => null),
            probe(() => api.subscriptions()),
            probe(() => api.httpRuns(1, 1)),
        ]);
        set({ info, hasSubscriptions: subs, hasHistory: hist, loaded: true });
    },
    presets: () => get().info?.checkPresets ?? CHECK_PRESETS,
}));
