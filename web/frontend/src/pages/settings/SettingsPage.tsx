import { useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { LogOut, Trash2, Bell } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Panel } from "@/components/common/Panel";
import { CheckRow } from "@/components/common/Field";
import { ConfirmButton } from "@/components/common/ConfirmButton";
import { useTheme, type Theme } from "@/components/theme-provider";
import { useServerStore } from "@/stores/serverStore";
import { useAuthStore, tokenExpiresAt } from "@/stores/authStore";
import { notificationsEnabled, notificationsSupported, setNotificationsEnabled } from "@/lib/notify";
import { cn } from "@/lib/utils";
import { useI18n, type Lang } from "@/i18n";

function Choice<T extends string>({ name, value, options, onChange }: { name: string; value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
    return (
        <div role="radiogroup" aria-label={name} className="inline-flex flex-wrap gap-1 rounded-lg border bg-background p-1">
            {options.map((o) => (
                <button key={o.value} type="button" role="radio" aria-checked={value === o.value} onClick={() => onChange(o.value)}
                    className={cn("rounded-md px-3 py-1.5 text-sm transition-colors focus-visible:outline-2", value === o.value ? "bg-primary text-primary-foreground" : "hover:bg-accent")}>
                    {o.label}
                </button>
            ))}
        </div>
    );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div className="grid gap-1 py-2.5 sm:grid-cols-[11rem_1fr] sm:gap-4">
            <dt className="text-sm text-muted-foreground">{label}</dt>
            <dd className="min-w-0 text-sm">{children}</dd>
        </div>
    );
}

const FORM_KEYS = ["httptest-configs-input", "proxy-configs-input", "cfscanner-subnets-input", "httptest-source", "httptest-sub", "proxy-source"];

export default function SettingsPage({ onLogout }: { onLogout?: () => void }) {
    const { t, lang, setLang } = useI18n();
    const { theme, setTheme } = useTheme();
    const info = useServerStore((s) => s.info);
    const { hasSubscriptions, hasHistory, loaded } = useServerStore(useShallow((s) => ({ hasSubscriptions: s.hasSubscriptions, hasHistory: s.hasHistory, loaded: s.loaded })));
    const token = useAuthStore((s) => s.token);
    const exp = tokenExpiresAt(token);
    const [notify, setNotify] = useState(notificationsEnabled());

    return (
        <div className="mx-auto grid max-w-4xl gap-4">
            <Panel title={t("Appearance")}>
                <dl className="divide-y">
                    <Row label={t("Theme")}>
                        <Choice<Theme> name={t("Theme")} value={theme} onChange={setTheme} options={[
                            { value: "system", label: t("Match system") }, { value: "light", label: t("Light") }, { value: "dark", label: t("Dark") },
                        ]} />
                    </Row>
                    <Row label={t("Language")}>
                        <Choice<Lang> name={t("Language")} value={lang} onChange={setLang} options={[{ value: "en", label: "English" }, { value: "fa", label: "فارسی" }]} />
                    </Row>
                </dl>
            </Panel>

            <Panel title={t("Notifications")}>
                {notificationsSupported() ? (
                    <CheckRow id="set-notify" label={t("Notify me when a long test or scan finishes")} hint={t("Only while this tab is in the background.")}>
                        <Checkbox id="set-notify" checked={notify} onCheckedChange={async (c) => {
                            const on = await setNotificationsEnabled(Boolean(c));
                            setNotify(on);
                            if (Boolean(c) && !on) toast.error(t("The browser blocked notifications for this site"));
                        }} />
                    </CheckRow>
                ) : (
                    <p className="flex items-center gap-2 text-sm text-muted-foreground"><Bell className="size-4" aria-hidden />{t("Notifications need HTTPS or localhost. Serve the panel over TLS to use them.")}</p>
                )}
            </Panel>

            <Panel title={t("Server")}>
                <dl className="divide-y">
                    <Row label={t("Version")}>{info?.version ?? <span className="text-muted-foreground">{loaded ? t("Not reported by this server") : "…"}</span>}</Row>
                    {info?.cores && <Row label={t("Cores")}><div className="flex flex-wrap gap-1">{info.cores.map((c) => <Badge key={c} variant="neutral">{c}</Badge>)}</div></Row>}
                    {info?.protocols && info.protocols.length > 0 && (
                        <Row label={t("Protocols")}>
                            <div className="flex flex-wrap gap-1">
                                {info.protocols.map((p) => <Badge key={p.scheme} variant="neutral" title={t("via {core}", { core: p.core })}>{p.scheme}</Badge>)}
                            </div>
                        </Row>
                    )}
                    {info?.buildTags && info.buildTags.length > 0 && <Row label={t("Build tags")}><span className="font-mono text-xs md:text-xs">{info.buildTags.join(" ")}</span></Row>}
                    {info?.listenAddr && <Row label={t("Listening on")}><span className="font-mono text-xs md:text-xs" dir="ltr">{info.tls ? "https" : "http"}://{info.listenAddr}</span></Row>}
                    {info && info.tls === false && info.listenAddr && !/^(127\.|\[::1\]|localhost)/.test(info.listenAddr) && (
                        <Row label={t("Warning")}><span className="text-semi">{t("The panel is reachable from the network without TLS. Passwords and tokens travel in clear text.")}</span></Row>
                    )}
                    <Row label={t("Features")}>
                        <div className="flex flex-wrap gap-1">
                            <Badge variant={hasSubscriptions ? "pass" : "neutral"}>{t("Subscriptions")}{hasSubscriptions ? "" : `: ${t("not available")}`}</Badge>
                            <Badge variant={hasHistory ? "pass" : "neutral"}>{t("History")}{hasHistory ? "" : `: ${t("not available")}`}</Badge>
                            {info?.dbAvailable === false && <Badge variant="semi">{t("Database unavailable")}</Badge>}
                        </div>
                    </Row>
                </dl>
            </Panel>

            <Panel title={t("Session and data")}>
                <dl className="divide-y">
                    {exp && <Row label={t("Session expires")}>{new Date(exp).toLocaleString()}</Row>}
                    <Row label={t("Saved form data")}>
                        <ConfirmButton title={t("Forget saved inputs?")} description={t("Clears the links and ranges this browser remembers for each page. Server data is not touched.")}
                            confirmLabel={t("Forget")} onConfirm={() => {
                                for (const k of FORM_KEYS) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
                                toast.success(t("Saved inputs cleared. Reload to see empty forms."));
                            }}>
                            <Trash2 aria-hidden />{t("Forget saved inputs")}
                        </ConfirmButton>
                    </Row>
                    {onLogout && <Row label={t("Account")}><Button variant="outline" size="sm" onClick={onLogout}><LogOut className="rtl:-scale-x-100" aria-hidden />{t("Log out")}</Button></Row>}
                </dl>
            </Panel>
        </div>
    );
}
