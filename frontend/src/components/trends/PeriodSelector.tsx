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

export default function PeriodSelector({
  value,
  onChange,
}: Props) {
  return (
    <div className="inline-flex rounded-lg border border-gray-200 dark:border-white/10 overflow-hidden">
      {PERIODS.map((p) => (
        <button
          key={p.value}
          onClick={() => onChange(p.value)}
          className={`px-4 py-1.5 text-sm font-medium transition-colors ${
            value === p.value
              ? "bg-primary-600 text-white"
              : "bg-white dark:bg-[#1a1a1a] text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-[#222]"
          }`}
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}
