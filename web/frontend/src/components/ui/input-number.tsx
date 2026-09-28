import * as React from "react"
import { Minus, Plus } from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "./button"

export interface InputNumberProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "onChange" | "value" | "min" | "max" | "step"> {
  value: number
  onChange: (value: number) => void
  min?: number
  max?: number
  step?: number
  /** Accessible name of the field, used for the +/- buttons. */
  label?: string
}

const clamp = (v: number, min: number | undefined, max: number | undefined) => {
  let out = v
  if (min !== undefined && out < min) out = min
  if (max !== undefined && out > max) out = max
  return out
}

// A text field (no native spinners) with +/- buttons. The draft text is local
// so the field can be cleared while typing; the value is clamped on blur only.
const InputNumber = React.forwardRef<HTMLInputElement, InputNumberProps>(
  ({ className, value, onChange, min, max, step = 1, disabled, label, id, ...props }, ref) => {
    const [draft, setDraft] = React.useState<string>(String(value))
    const focused = React.useRef(false)

    React.useEffect(() => {
      if (!focused.current) setDraft(String(value))
    }, [value])

    const commit = (raw: string) => {
      const n = Number.parseInt(raw, 10)
      const next = Number.isNaN(n) ? clamp(value, min, max) : clamp(n, min, max)
      setDraft(String(next))
      if (next !== value) onChange(next)
    }

    const stepBy = (dir: 1 | -1) => {
      if (disabled) return
      const base = Number.parseInt(draft, 10)
      const next = clamp((Number.isNaN(base) ? value : base) + dir * step, min, max)
      setDraft(String(next))
      onChange(next)
    }

    return (
      <div
        className={cn(
          "relative flex h-9 w-full max-w-[11rem] items-center rounded-md border border-input bg-transparent shadow-xs focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/40 dark:bg-input/30",
          disabled && "opacity-50",
          className
        )}
      >
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          tabIndex={-1}
          className="h-full rounded-e-none border-e"
          onClick={() => stepBy(-1)}
          disabled={disabled || (min !== undefined && value <= min)}
          aria-label={label ? `Decrease ${label}` : "Decrease"}
        >
          <Minus className="size-3.5" />
        </Button>
        <input
          ref={ref}
          id={id}
          type="text"
          inputMode="numeric"
          role="spinbutton"
          aria-valuenow={value}
          aria-valuemin={min}
          aria-valuemax={max}
          value={draft}
          disabled={disabled}
          onFocus={() => { focused.current = true }}
          onChange={(e) => {
            const raw = e.target.value.replace(/[^\d-]/g, "")
            setDraft(raw)
            const n = Number.parseInt(raw, 10)
            // Live-update while the number is in range; out-of-range waits for blur.
            if (!Number.isNaN(n) && n === clamp(n, min, max)) onChange(n)
          }}
          onBlur={(e) => { focused.current = false; commit(e.target.value) }}
          onKeyDown={(e) => {
            if (e.key === "ArrowUp") { e.preventDefault(); stepBy(1) }
            else if (e.key === "ArrowDown") { e.preventDefault(); stepBy(-1) }
            else if (e.key === "Enter") commit((e.target as HTMLInputElement).value)
          }}
          className="num h-full w-full min-w-0 bg-transparent px-1 text-center text-sm outline-none disabled:cursor-not-allowed"
          {...props}
        />
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          tabIndex={-1}
          className="h-full rounded-s-none border-s"
          onClick={() => stepBy(1)}
          disabled={disabled || (max !== undefined && value >= max)}
          aria-label={label ? `Increase ${label}` : "Increase"}
        >
          <Plus className="size-3.5" />
        </Button>
      </div>
    )
  }
)
InputNumber.displayName = "InputNumber"

export { InputNumber }
