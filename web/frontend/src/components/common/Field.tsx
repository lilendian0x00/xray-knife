import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { Rich } from "./Rich";

interface FieldProps {
    id: string;
    label: React.ReactNode;
    hint?: React.ReactNode;
    error?: string | null;
    className?: string;
    children: React.ReactNode;
}

/**
 * Label + control + hint/error. The control must use the same `id`; the hint
 * element's id is `${id}-hint`.
 */
export function Field({ id, label, hint, error, className, children }: FieldProps) {
    return (
        <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
            <Label htmlFor={id} className="text-[13px] font-medium text-foreground/90">{label}</Label>
            {children}
            {error ? (
                <p id={`${id}-hint`} role="alert" className="text-xs text-fail">{error}</p>
            ) : hint ? (
                <p id={`${id}-hint`} className="text-xs text-muted-foreground">{typeof hint === "string" ? <Rich text={hint} /> : hint}</p>
            ) : null}
        </div>
    );
}

/** A checkbox row with its label and an optional hint underneath. */
export function CheckRow({ id, label, hint, children }: { id: string; label: React.ReactNode; hint?: React.ReactNode; children: React.ReactNode }) {
    return (
        <div className="flex items-start gap-2.5">
            <div className="pt-0.5">{children}</div>
            <div className="min-w-0">
                <Label htmlFor={id} className="cursor-pointer text-sm font-normal leading-5">{label}</Label>
                {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
            </div>
        </div>
    );
}
