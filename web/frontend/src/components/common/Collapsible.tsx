import { useId, useState } from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface CollapsibleProps {
    title: React.ReactNode;
    /** Short summary shown next to the title while collapsed. */
    summary?: React.ReactNode;
    defaultOpen?: boolean;
    open?: boolean;
    onOpenChange?: (open: boolean) => void;
    children: React.ReactNode;
    className?: string;
}

export function Collapsible({ title, summary, defaultOpen = false, open: controlled, onOpenChange, children, className }: CollapsibleProps) {
    const [inner, setInner] = useState(defaultOpen);
    const open = controlled ?? inner;
    const id = useId();
    const toggle = () => {
        const next = !open;
        if (controlled === undefined) setInner(next);
        onOpenChange?.(next);
    };
    return (
        <section className={cn("rounded-md border", className)}>
            <h3 className="m-0">
                <button
                    type="button"
                    aria-expanded={open}
                    aria-controls={id}
                    onClick={toggle}
                    className="flex w-full items-center gap-2 rounded-md px-3 py-2.5 text-start text-sm font-medium hover:bg-accent/60 focus-visible:outline-2"
                >
                    <ChevronDown aria-hidden className={cn("size-4 shrink-0 text-muted-foreground transition-transform", !open && "-rotate-90 rtl:rotate-90")} />
                    <span>{title}</span>
                    {!open && summary && <span className="ms-auto truncate text-xs font-normal text-muted-foreground">{summary}</span>}
                </button>
            </h3>
            <div id={id} hidden={!open} className="space-y-4 border-t px-3 pb-3 pt-3">
                {open && children}
            </div>
        </section>
    );
}
