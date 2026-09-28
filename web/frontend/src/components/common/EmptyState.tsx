import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Rich } from "./Rich";

export function EmptyState({ icon: Icon, title, children, className }: { icon: LucideIcon; title: string; children?: React.ReactNode; className?: string }) {
    return (
        <div className={cn("flex flex-col items-center justify-center gap-2 px-6 py-12 text-center", className)}>
            <Icon className="size-7 text-muted-foreground/70" aria-hidden />
            <p className="text-sm font-medium">{title}</p>
            {children && <div className="max-w-sm text-xs text-muted-foreground">{typeof children === "string" ? <Rich text={children} /> : children}</div>}
        </div>
    );
}
