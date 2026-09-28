/** Renders `backticked` spans of a UI string as inline code. */
export function Rich({ text }: { text: string }) {
    const parts = text.split(/(`[^`]+`)/g);
    return (
        <>
            {parts.map((p, i) =>
                p.startsWith("`") && p.endsWith("`") && p.length > 2
                    ? <code key={i} className="rounded bg-muted px-1 py-px font-mono text-[0.92em] text-foreground" dir="ltr">{p.slice(1, -1)}</code>
                    : p,
            )}
        </>
    );
}
