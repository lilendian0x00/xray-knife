import { useDeferredValue, useMemo, useRef, useState } from "react";
import { FileUp, Sparkles, Eraser } from "lucide-react";
import { toast } from "sonner";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { analyzeLinks, analyzeSubnets } from "@/lib/links";
import { cn, formatCount } from "@/lib/utils";
import { useT } from "@/i18n";

const MAX_FILE_BYTES = 32 * 1024 * 1024;

interface LinkInputProps {
    id: string;
    label: string;
    value: string;
    onChange: (v: string) => void;
    kind?: "links" | "subnets";
    disabled?: boolean;
    placeholder?: string;
    rows?: number;
    /** Extra action rendered at the end of the label row (e.g. "Load CF ranges"). */
    action?: React.ReactNode;
    tooLarge?: boolean;
}

export function LinkInput({ id, label, value, onChange, kind = "links", disabled, placeholder, rows = 8, action, tooLarge }: LinkInputProps) {
    const t = useT();
    const fileRef = useRef<HTMLInputElement>(null);
    const [dragging, setDragging] = useState(false);
    // Analysis of a pasted 40k-line list must not block typing.
    const deferred = useDeferredValue(value);
    const stats = useMemo(() => {
        if (kind === "subnets") {
            const a = analyzeSubnets(deferred);
            return { valid: a.subnets.length, duplicates: a.duplicates, invalid: a.invalid, cleaned: a.subnets, extra: a.wideIPv6.length ? t("{n} wide IPv6 ranges", { n: a.wideIPv6.length }) : a.ipv4Addresses ? t("{n} IPv4 addresses", { n: formatCount(a.ipv4Addresses) }) : "" };
        }
        const a = analyzeLinks(deferred);
        return { valid: a.links.length, duplicates: a.duplicates, invalid: a.invalid, cleaned: a.links, extra: "" };
    }, [deferred, kind, t]);

    const readFile = async (file: File) => {
        if (file.size > MAX_FILE_BYTES) {
            toast.error(t("File is too large"), { description: t("The limit is 32 MB.") });
            return;
        }
        const text = await file.text();
        const joined = value.trim() ? `${value.trimEnd()}\n${text}` : text;
        onChange(joined);
        toast.success(t("Added {name}", { name: file.name }));
    };

    const onDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setDragging(false);
        if (disabled) return;
        const file = e.dataTransfer.files?.[0];
        if (file) void readFile(file);
    };

    const hasProblems = stats.duplicates > 0 || stats.invalid.length > 0;
    const noun = kind === "subnets" ? (stats.valid === 1 ? t("range") : t("ranges")) : (stats.valid === 1 ? t("link") : t("links"));

    return (
        <div className="flex flex-col gap-1.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
                <Label htmlFor={id} className="text-[13px] font-medium">{label}</Label>
                <div className="flex items-center gap-1">
                    {action}
                    <Button type="button" variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => fileRef.current?.click()} disabled={disabled}>
                        <FileUp aria-hidden />{t("Upload .txt")}
                    </Button>
                    <input
                        ref={fileRef}
                        type="file"
                        accept=".txt,.list,.conf,text/plain"
                        className="hidden"
                        tabIndex={-1}
                        onChange={(e) => {
                            const f = e.target.files?.[0];
                            if (f) void readFile(f);
                            e.target.value = "";
                        }}
                    />
                </div>
            </div>
            <div
                className="relative"
                onDragOver={(e) => { e.preventDefault(); if (!disabled) setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
            >
                <Textarea
                    id={id}
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    disabled={disabled}
                    placeholder={placeholder}
                    rows={rows}
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                    aria-describedby={`${id}-stats`}
                    className="min-h-32 resize-y whitespace-pre font-mono text-[12.5px] leading-5 md:text-[12.5px]"
                    dir="ltr"
                />
                {dragging && (
                    <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-md border-2 border-dashed border-primary bg-primary/5 text-sm font-medium text-primary">
                        {t("Drop the file to add its lines")}
                    </div>
                )}
            </div>
            <div id={`${id}-stats`} className="flex min-h-7 flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground" aria-live="polite">
                <span className={cn("num", stats.valid > 0 && "text-foreground")}>
                    {t("{n} valid {noun}", { n: formatCount(stats.valid), noun })}
                </span>
                {stats.duplicates > 0 && <span className="num text-semi">{stats.duplicates === 1 ? t("1 duplicate") : t("{n} duplicates", { n: formatCount(stats.duplicates) })}</span>}
                {stats.invalid.length > 0 && (
                    <span className="num text-fail" title={stats.invalid.slice(0, 5).join("\n")}>
                        {t("{n} not recognised", { n: formatCount(stats.invalid.length) })}
                    </span>
                )}
                {stats.extra && <span className="num">{stats.extra}</span>}
                {tooLarge && <span className="text-semi">{t("Too large to remember after reload")}</span>}
                <span className="ms-auto flex gap-1">
                    {hasProblems && (
                        <Button type="button" variant="ghost" size="sm" className="h-7 px-2 text-xs" disabled={disabled} onClick={() => onChange(stats.cleaned.join("\n"))}>
                            <Sparkles aria-hidden />{t("Clean up")}
                        </Button>
                    )}
                    {value && (
                        <Button type="button" variant="ghost" size="sm" className="h-7 px-2 text-xs" disabled={disabled} onClick={() => onChange("")}>
                            <Eraser aria-hidden />{t("Clear")}
                        </Button>
                    )}
                </span>
            </div>
        </div>
    );
}
