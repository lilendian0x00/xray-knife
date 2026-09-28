import { create } from 'zustand';

export type LogLevel = 'success' | 'error' | 'warning' | 'info' | 'progress' | 'plain';

export interface LogEntry {
    id: number;
    /** Local receive time, epoch ms. */
    at: number;
    /** HH:MM:SS from the server line when present. */
    time: string;
    level: LogLevel;
    /** Service tag such as PROXY or HTTP-TEST when the line carries one. */
    service: string;
    text: string;
}

const MAX_LINES = 5000;
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\u001b\[[0-9;]*[A-Za-z]/g;

const SYMBOLS: [string, LogLevel][] = [
    ['✅', 'success'],
    ['🎉', 'success'],
    ['❌', 'error'],
    ['⚠️', 'warning'],
    ['⚙️', 'progress'],
    ['ℹ️', 'info'],
];

let nextId = 1;

export function parseLogLine(raw: string): Omit<LogEntry, 'id' | 'at'> {
    let text = raw.replace(ANSI_RE, '').trim();
    let level: LogLevel = 'plain';
    for (const [sym, lvl] of SYMBOLS) {
        if (text.startsWith(sym)) {
            level = lvl;
            text = text.slice(sym.length).trim();
            break;
        }
    }
    let time = '';
    const tm = /^(\d{2}:\d{2}:\d{2})\s+/.exec(text);
    if (tm) {
        time = tm[1];
        text = text.slice(tm[0].length);
    }
    let service = '';
    const sm = /^\[([A-Z][A-Z0-9_-]{1,20})\]\s*/.exec(text);
    if (sm) {
        service = sm[1];
        text = text.slice(sm[0].length);
    }
    if (level === 'plain') {
        if (/\b(error|failed|panic|critical)\b/i.test(text)) level = 'error';
        else if (/\bwarn(ing)?\b/i.test(text)) level = 'warning';
    }
    return { time, level, service, text };
}

interface LogState {
    entries: LogEntry[];
    /** Lines dropped from the front because of MAX_LINES. */
    dropped: number;
    push: (lines: string[]) => void;
    note: (text: string, level?: LogLevel) => void;
    clear: () => void;
}

export const useLogStore = create<LogState>()((set) => ({
    entries: [],
    dropped: 0,
    push: (lines) => set((st) => {
        if (lines.length === 0) return st;
        const at = Date.now();
        const added: LogEntry[] = [];
        for (const chunk of lines) {
            for (const line of chunk.split(/\r?\n/)) {
                const parsed = parseLogLine(line);
                // Blank lines and bare ANSI resets carry nothing worth a row.
                if (parsed.text === '') continue;
                added.push({ id: nextId++, at, ...parsed });
            }
        }
        if (added.length === 0) return st;
        let entries = st.entries.concat(added);
        let dropped = st.dropped;
        if (entries.length > MAX_LINES) {
            dropped += entries.length - MAX_LINES;
            entries = entries.slice(entries.length - MAX_LINES);
        }
        return { entries, dropped };
    }),
    // Client-side notes (connection state etc.), shown in the same list.
    note: (text, level = 'info') => set((st) => {
        const now = new Date();
        const entry: LogEntry = {
            id: nextId++, at: now.getTime(), level, service: 'PANEL', text,
            time: now.toTimeString().slice(0, 8),
        };
        const entries = st.entries.length >= MAX_LINES ? st.entries.slice(1).concat(entry) : st.entries.concat(entry);
        return { entries };
    }),
    clear: () => set({ entries: [], dropped: 0 }),
}));
