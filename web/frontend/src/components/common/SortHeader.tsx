import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/utils";

export type SortDir = "asc" | "desc";

interface SortHeaderProps<F extends string> {
    field: F;
    active: F;
    dir: SortDir;
    onSort: (f: F) => void;
    children: React.ReactNode;
    className?: string;
    align?: "start" | "end";
}

/** A column header that sorts with mouse or keyboard and reports aria-sort. */
export function SortHeader<F extends string>({ field, active, dir, onSort, children, className, align = "start" }: SortHeaderProps<F>) {
    const isActive = field === active;
    const Icon = !isActive ? ArrowUpDown : dir === "asc" ? ArrowUp : ArrowDown;
    return (
        <th
            scope="col"
            aria-sort={isActive ? (dir === "asc" ? "ascending" : "descending") : "none"}
            className={cn("h-9 px-2 text-xs font-medium text-muted-foreground", align === "end" ? "text-end" : "text-start", className)}
        >
            <button
                type="button"
                onClick={() => onSort(field)}
                className={cn("inline-flex items-center gap-1 rounded px-1 py-0.5 hover:text-foreground focus-visible:outline-2", isActive && "text-foreground", align === "end" && "flex-row-reverse")}
            >
                {children}
                <Icon aria-hidden className={cn("size-3", !isActive && "opacity-40")} />
            </button>
        </th>
    );
}
