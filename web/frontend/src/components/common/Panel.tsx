import { cn } from "@/lib/utils";

// A page section: a heading row (title, optional description, actions) over
// its content. Deliberately lighter than a card so a page doesn't read as a
// stack of identical boxes.
export function Panel({ title, description, actions, children, className, bodyClassName, as: As = "section", headingLevel = 2 }: {
    title?: React.ReactNode;
    description?: React.ReactNode;
    actions?: React.ReactNode;
    children: React.ReactNode;
    className?: string;
    bodyClassName?: string;
    as?: "section" | "div";
    headingLevel?: 2 | 3;
}) {
    const H = headingLevel === 2 ? "h2" : "h3";
    return (
        <As className={cn("min-w-0 rounded-lg border bg-card text-card-foreground", className)}>
            {(title || actions) && (
                <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b px-4 py-3">
                    <div className="min-w-0">
                        {title && <H className="text-[15px] font-semibold leading-6">{title}</H>}
                        {description && <p className="text-xs text-muted-foreground">{description}</p>}
                    </div>
                    {actions && <div className="flex flex-wrap items-center gap-1.5">{actions}</div>}
                </header>
            )}
            <div className={cn("p-4", bodyClassName)}>{children}</div>
        </As>
    );
}
