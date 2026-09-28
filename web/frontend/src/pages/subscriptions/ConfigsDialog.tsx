import { useEffect, useState } from "react";
import { Loader2, Search, ChevronLeft, ChevronRight } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/common/CopyButton";
import { api, type Subscription, type SubscriptionConfig, type Paginated } from "@/services/api";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { errorMessage, formatCount } from "@/lib/utils";
import { useT } from "@/i18n";

const PER_PAGE = 100;

export function ConfigsDialog({ subscription, onClose }: { subscription: Subscription | null; onClose: () => void }) {
    const t = useT();
    const [page, setPage] = useState(1);
    const [query, setQuery] = useState("");
    const q = useDebouncedValue(query.trim(), 300);
    const [data, setData] = useState<Paginated<SubscriptionConfig> | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const id = subscription?.id;

    useEffect(() => { setPage(1); }, [q, id]);
    useEffect(() => {
        if (!id) { setData(null); return; }
        let live = true;
        setLoading(true);
        api.subscriptionConfigs(id, { q: q || undefined, page, per_page: PER_PAGE })
            .then((d) => { if (live) { setData(d); setError(null); } })
            .catch((err) => { if (live) setError(errorMessage(err)); })
            .finally(() => { if (live) setLoading(false); });
        return () => { live = false; };
    }, [id, q, page]);

    const pages = data ? Math.max(1, Math.ceil(data.total / PER_PAGE)) : 1;
    return (
        <Dialog open={!!subscription} onOpenChange={(o) => !o && onClose()}>
            <DialogContent className="sm:max-w-3xl">
                <DialogHeader>
                    <DialogTitle>{subscription?.remark || t("Subscription configs")}</DialogTitle>
                    <DialogDescription>{data ? t("{n} configs", { n: formatCount(data.total) }) : "\u00a0"}</DialogDescription>
                </DialogHeader>
                <div className="flex items-center gap-2">
                    <div className="relative flex-1">
                        <Search className="pointer-events-none absolute start-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
                        <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Search remark or address")} aria-label={t("Search configs")} className="h-8 ps-7 text-xs" />
                    </div>
                    <CopyButton text={() => (data?.items ?? []).map((c) => c.link).join("\n")} label={t("Copy links on this page")} done={t("Links copied")} size="sm" variant="outline" disabled={!data?.items.length}>{t("Copy page")}</CopyButton>
                </div>
                <div className="max-h-[55dvh] overflow-auto rounded-md border">
                    {error ? <p role="alert" className="p-4 text-sm text-fail">{error}</p> : loading && !data ? (
                        <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" aria-hidden />{t("Loading…")}</p>
                    ) : (
                        <ul className="divide-y text-sm">
                            {data?.items.map((c) => (
                                <li key={c.id} className="flex items-center gap-3 px-3 py-2">
                                    <span className="w-20 shrink-0 text-xs text-muted-foreground">{c.protocol}</span>
                                    <span className="min-w-0 flex-1 truncate">{c.remark || <span className="font-mono text-xs text-muted-foreground" dir="ltr">{c.link.slice(0, 64)}</span>}</span>
                                    <CopyButton text={c.link} label={t("Copy link")} done={t("Link copied")} />
                                </li>
                            ))}
                            {data && data.items.length === 0 && <li className="p-4 text-muted-foreground">{t("No configs match.")}</li>}
                        </ul>
                    )}
                </div>
                {pages > 1 && (
                    <div className="flex items-center justify-end gap-2 text-xs">
                        <Button size="icon-sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label={t("Previous page")}><ChevronLeft className="rtl:-scale-x-100" aria-hidden /></Button>
                        <span className="num">{t("Page {p} of {n}", { p: page, n: pages })}</span>
                        <Button size="icon-sm" variant="outline" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label={t("Next page")}><ChevronRight className="rtl:-scale-x-100" aria-hidden /></Button>
                    </div>
                )}
            </DialogContent>
        </Dialog>
    );
}
