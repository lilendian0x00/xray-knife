import * as React from "react"
import { Minus, Plus } from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export interface InputNumberProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value'> {
  value: number
  onChange: (value: number) => void
  min?: number
  max?: number
  step?: number
}

const InputNumber = React.forwardRef<HTMLInputElement, InputNumberProps>(
  ({ className, value, onChange, min = -Infinity, max = Infinity, step = 1, disabled, ...props }, ref) => {
    
    const handleStep = (direction: 'up' | 'down') => {
      if (disabled) return;
      let newValue = value + (direction === 'up' ? step : -step);
      newValue = Math.max(min, Math.min(newValue, max));
      onChange(newValue);
    };
    
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const stringValue = e.target.value;
      if (stringValue === "") {
        onChange(min); // Or handle as a special case, e.g., onChange(null) if your logic supports it
        return;
      }
      const numValue = parseInt(stringValue, 10);
      if (!isNaN(numValue)) {
        onChange(numValue);
      }
    };
    
    const handleBlur = () => {
        let finalValue = value;
        if (finalValue > max) finalValue = max;
        if (finalValue < min) finalValue = min;
        onChange(finalValue);
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "ArrowUp") {
        e.preventDefault();
        handleStep("up");
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        handleStep("down");
      }
    };

    return (
      <div
        className={cn(
          "relative flex max-w-[10rem] items-center rounded-md border border-input shadow-xs focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50",
          { "opacity-50": disabled },
          className
        )}
      >
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-full rounded-r-none border-r data-[disabled=true]:pointer-events-auto data-[disabled=true]:cursor-pointer"
          onClick={() => handleStep('down')}
          disabled={disabled || value <= min}
        >
          <Minus className="size-4" />
        </Button>
        <Input
          ref={ref}
          type="text" // Use text to hide native spinners
          role="spinbutton"
          aria-valuenow={value}
          aria-valuemin={min}
          aria-valuemax={max}
          inputMode="numeric"
          pattern="[0-9]*"
          value={value}
          onChange={handleInputChange}
          onBlur={handleBlur}
          onKeyDown={handleKeyDown}
          disabled={disabled}
          className="h-auto border-0 p-2 text-center shadow-none focus-visible:ring-0"
          {...props}
        />
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-full rounded-l-none border-l data-[disabled=true]:pointer-events-auto data-[disabled=true]:cursor-pointer"
          onClick={() => handleStep('up')}
          disabled={disabled || value >= max}
        >
          <Plus className="size-4" />
        </Button>
      </div>
    )
  }
)
InputNumber.displayName = "InputNumber"

export { InputNumber }