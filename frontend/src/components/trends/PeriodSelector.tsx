import type { Period } from "@/hooks";

interface Props {
  value: Period;
  onChange: (period: Period) => void;
}

const PERIODS: { value: Period; label: string }[] = [
  { value: "7d", label: "7 Days" },
  { value: "30d", label: "30 Days" },
  { value: "90d", label: "90 Days" },
];

export default function PeriodSelector({ value, onChange }: Props) {
  return (
    <div className="inline-flex rounded-pill border border-ghost-cream dark:border-white/10 bg-canvas-cream dark:bg-ink-black overflow-hidden p-0.5 gap-0.5">
      {PERIODS.map((p) => (
        <button
          key={p.value}
          onClick={() => onChange(p.value)}
          className={`px-4 py-1.5 text-sm font-medium transition-colors rounded-pill ${
            value === p.value
              ? "bg-ink-black text-canvas-cream dark:bg-canvas-cream dark:text-ink-black"
              : "text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5"
          }`}
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}
