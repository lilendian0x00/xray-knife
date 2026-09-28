import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { copyText, errorMessage } from "@/lib/utils";

interface CopyButtonProps {
    text: string | (() => string);
    label: string;
    /** Toast text on success; defaults to "Copied". */
    done?: string;
    size?: "icon" | "icon-sm" | "sm";
    variant?: "ghost" | "outline" | "secondary";
    children?: React.ReactNode;
    disabled?: boolean;
    className?: string;
}

export function CopyButton({ text, label, done = "Copied", size = "icon-sm", variant = "ghost", children, disabled, className }: CopyButtonProps) {
    const [ok, setOk] = useState(false);
    const onClick = async () => {
        try {
            await copyText(typeof text === "function" ? text() : text);
            setOk(true);
            window.setTimeout(() => setOk(false), 1200);
            toast.success(done);
        } catch (err) {
            toast.error("Could not copy", { description: errorMessage(err) });
        }
    };
    const Icon = ok ? Check : Copy;
    return (
        <Button type="button" size={size} variant={variant} onClick={onClick} disabled={disabled} aria-label={children ? undefined : label} title={label} className={className}>
            <Icon className={ok ? "text-pass" : undefined} aria-hidden />
            {children}
        </Button>
    );
}
