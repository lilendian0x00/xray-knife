import { useMemo } from "react";
import { encode } from "uqr";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CopyButton } from "./CopyButton";
import { useT } from "@/i18n";

// QR payloads above ~2.9 kB don't fit a version-40 code; say so instead of throwing.
const MAX_QR_BYTES = 2800;

function QrSvg({ text }: { text: string }) {
    const qr = useMemo(() => {
        try {
            return encode(text, { ecc: "L", border: 2 });
        } catch {
            return null;
        }
    }, [text]);
    if (!qr) return null;
    const { size, data } = qr;
    // One path for all dark modules keeps the DOM small.
    let d = "";
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            if (data[y][x]) d += `M${x} ${y}h1v1h-1z`;
        }
    }
    return (
        <svg viewBox={`0 0 ${size} ${size}`} role="img" aria-label="QR code" className="aspect-square w-full max-w-[18rem] rounded-md bg-white p-1" shapeRendering="crispEdges">
            <path d={d} fill="#0e2233" />
        </svg>
    );
}

interface QrDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    text: string;
    title?: string;
}

export function QrDialog({ open, onOpenChange, text, title }: QrDialogProps) {
    const t = useT();
    const tooLong = new TextEncoder().encode(text).length > MAX_QR_BYTES;
    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-sm">
                <DialogHeader>
                    <DialogTitle>{title ?? t("Scan with your phone")}</DialogTitle>
                    <DialogDescription>{t("Import it in v2rayNG, Hiddify, Streisand or any client that reads share links.")}</DialogDescription>
                </DialogHeader>
                <div className="flex flex-col items-center gap-3">
                    {tooLong ? (
                        <p className="text-sm text-muted-foreground">{t("This link is too long for a QR code. Copy it instead.")}</p>
                    ) : (
                        open && <QrSvg text={text} />
                    )}
                    <p className="w-full break-all rounded bg-muted px-2 py-1.5 font-mono text-[11px] text-muted-foreground" dir="ltr">{text.length > 240 ? `${text.slice(0, 240)}…` : text}</p>
                    <CopyButton text={text} label={t("Copy link")} done={t("Link copied")} size="sm" variant="outline">{t("Copy link")}</CopyButton>
                </div>
            </DialogContent>
        </Dialog>
    );
}
