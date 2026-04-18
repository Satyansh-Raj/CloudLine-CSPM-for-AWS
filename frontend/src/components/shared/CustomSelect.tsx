import { useEffect, useRef, useState } from "react";

export interface SelectOption {
  value: string;
  label: string;
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  className?: string;
  "aria-label"?: string;
}

export default function CustomSelect({
  value,
  onChange,
  options,
  className = "",
  "aria-label": ariaLabel,
}: Props) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const selected = options.find((o) => o.value === value);

  useEffect(() => {
    function onOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", onOutside);
    return () => document.removeEventListener("mousedown", onOutside);
  }, [open]);

  function pick(v: string) {
    onChange(v);
    setOpen(false);
  }

  return (
    <div ref={ref} className={`relative ${className}`}>
      {/* Trigger */}
      <button
        type="button"
        role="combobox"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((p) => !p)}
        className="flex items-center justify-between gap-2 w-full rounded-pill border border-ghost-cream dark:border-white/10 bg-canvas-cream dark:bg-ink-black text-sm text-ink-black dark:text-canvas-cream px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink-black/30 dark:focus:ring-canvas-cream/20 min-w-[120px]"
      >
        <span className="truncate">
          {selected?.label ?? options[0]?.label ?? ""}
        </span>
        <svg
          className={`w-3.5 h-3.5 shrink-0 transition-transform duration-150 ${open ? "rotate-180" : ""}`}
          viewBox="0 0 10 6"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M1 1l4 4 4-4" />
        </svg>
      </button>

      {/* Dropdown — always in DOM for accessibility/tests, hidden when closed */}
      <ul
        role="listbox"
        aria-label={ariaLabel}
        hidden={!open}
        className={[
          "absolute z-50 mt-1 w-full min-w-[140px]",
          "bg-lifted-cream dark:bg-ink-black",
          "border border-ghost-cream dark:border-white/10",
          "rounded-xl shadow-elev-2 py-1 max-h-64 overflow-y-auto",
          open ? "" : "hidden",
        ].join(" ")}
      >
        {options.map((opt) => {
          const active = opt.value === value;
          return (
            <li
              key={opt.value}
              role="option"
              aria-selected={active}
              onClick={() => pick(opt.value)}
              className={[
                "px-3 py-1.5 text-sm cursor-pointer select-none",
                active
                  ? "bg-ink-black text-canvas-cream dark:bg-canvas-cream dark:text-ink-black font-medium"
                  : "text-ink-black dark:text-canvas-cream hover:bg-ink-black hover:text-canvas-cream dark:hover:bg-canvas-cream dark:hover:text-ink-black",
              ].join(" ")}
            >
              {opt.label}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
