import { InputNumber } from "@/components/ui/input-number";
import type { FragmentRange } from "@/types/settings";

interface RangeInputProps {
    id: string;
    label: string;
    value: FragmentRange;
    onChange: (r: FragmentRange) => void;
    min?: number;
    max?: number;
    step?: number;
    unit?: string;
    disabled?: boolean;
}

/** Two numbers, "from" and "to", read by xray as an inclusive range. */
export function RangeInput({ id, label, value, onChange, min = 0, max = 65535, step = 1, unit, disabled }: RangeInputProps) {
    return (
        <fieldset className="flex min-w-0 flex-col gap-1.5" disabled={disabled}>
            <legend className="mb-1.5 text-[13px] font-medium">
                {label}{unit && <span className="font-normal text-muted-foreground"> ({unit})</span>}
            </legend>
            <div className="flex items-center gap-2">
                <InputNumber id={`${id}-min`} aria-label={`${label} from`} label={`${label} from`} value={value.min} min={min} max={max} step={step}
                    onChange={(v) => onChange({ min: v, max: Math.max(v, value.max) })} />
                <span aria-hidden className="text-muted-foreground">–</span>
                <InputNumber id={`${id}-max`} aria-label={`${label} to`} label={`${label} to`} value={value.max} min={min} max={max} step={step}
                    onChange={(v) => onChange({ min: Math.min(v, value.min), max: v })} />
            </div>
        </fieldset>
    );
}
