// The xray-knife mark: a blade crossing a scan line, drawn as an X.
export function BrandMark({ className }: { className?: string }) {
    return (
        <svg viewBox="0 0 32 32" className={className} aria-hidden fill="none">
            <rect x="1" y="1" width="30" height="30" rx="8" className="fill-primary" />
            <path d="M9 9l14 14" stroke="currentColor" strokeWidth="3" strokeLinecap="round" className="text-primary-foreground" />
            <path d="M23 9L13.5 18.5l-2 5.5 5.5-2L26.5 12.5z" className="fill-primary-foreground" opacity=".9" />
        </svg>
    );
}
