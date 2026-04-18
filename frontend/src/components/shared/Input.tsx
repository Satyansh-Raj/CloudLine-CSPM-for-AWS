import { forwardRef, type InputHTMLAttributes } from "react";

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

const Input = forwardRef<HTMLInputElement, Props>(
  ({ label, error, className = "", id, ...props }, ref) => (
    <div className="flex flex-col gap-1">
      {label && (
        <label
          htmlFor={id}
          className="text-eyebrow font-medium tracking-eyebrow uppercase text-slate-gray"
        >
          {label}
        </label>
      )}
      <input
        ref={ref}
        id={id}
        className={`px-5 py-3 rounded-pill border bg-lifted-cream text-ink-black placeholder:text-slate-gray focus:outline-none transition-colors text-sm ${error ? "border-signal-orange" : "border-dust-taupe focus:border-ink-black"} ${className}`}
        {...props}
      />
      {error && (
        <span className="text-xs text-signal-orange">{error}</span>
      )}
    </div>
  ),
);

Input.displayName = "Input";

export default Input;
