import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useT } from "@/i18n";

interface ConfirmButtonProps {
    title: string;
    description: React.ReactNode;
    confirmLabel: string;
    onConfirm: () => void | Promise<void>;
    children: React.ReactNode;
    variant?: "default" | "outline" | "ghost" | "stop" | "destructive" | "secondary";
    size?: "default" | "sm" | "icon" | "icon-sm";
    disabled?: boolean;
    destructive?: boolean;
    "aria-label"?: string;
    className?: string;
}

export function ConfirmButton({ title, description, confirmLabel, onConfirm, children, variant = "outline", size = "sm", disabled, destructive = true, className, ...rest }: ConfirmButtonProps) {
    const t = useT();
    const [open, setOpen] = useState(false);
    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button variant={variant} size={size} disabled={disabled} aria-label={rest["aria-label"]} className={className}>{children}</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle>{title}</DialogTitle>
                    <DialogDescription>{description}</DialogDescription>
                </DialogHeader>
                <DialogFooter>
                    <DialogClose asChild><Button variant="secondary">{t("Cancel")}</Button></DialogClose>
                    <Button variant={destructive ? "destructive" : "default"} onClick={async () => { setOpen(false); await onConfirm(); }}>{confirmLabel}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

/** Controlled variant, for confirmations opened from a menu item. */
export function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel, onConfirm, destructive = true }: {
    open: boolean;
    onOpenChange: (o: boolean) => void;
    title: string;
    description: React.ReactNode;
    confirmLabel: string;
    onConfirm: () => void | Promise<void>;
    destructive?: boolean;
}) {
    const t = useT();
    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle>{title}</DialogTitle>
                    <DialogDescription>{description}</DialogDescription>
                </DialogHeader>
                <DialogFooter>
                    <DialogClose asChild><Button variant="secondary">{t("Cancel")}</Button></DialogClose>
                    <Button variant={destructive ? "destructive" : "default"} onClick={async () => { onOpenChange(false); await onConfirm(); }}>{confirmLabel}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
