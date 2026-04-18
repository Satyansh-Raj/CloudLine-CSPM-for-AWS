interface FilterValues {
  severity: string;
  domain: string;
}

interface Props {
  filters: FilterValues;
  onChange: (filters: FilterValues) => void;
}

const SEVERITIES = ["", "critical", "high", "medium", "low"];
const DOMAINS = [
  "",
  "identity",
  "compute",
  "data_protection",
  "network",
  "logging_monitoring",
  "detection",
];

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-gray mb-1">
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="block w-full rounded-pill border border-ghost-cream dark:border-white/10 bg-canvas-cream dark:bg-ink-black text-sm text-ink-black dark:text-canvas-cream px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink-black"
      >
        {options.map((opt) => (
          <option key={opt} value={opt}>
            {opt === ""
              ? "All"
              : opt
                  .replace(/_/g, " ")
                  .replace(/\b\w/g, (c) => c.toUpperCase())}
          </option>
        ))}
      </select>
    </div>
  );
}

export type { FilterValues };

export default function ViolationFilters({ filters, onChange }: Props) {
  return (
    <div className="flex flex-wrap gap-4">
      <Select
        label="Severity"
        value={filters.severity}
        options={SEVERITIES}
        onChange={(severity) => onChange({ ...filters, severity })}
      />
      <Select
        label="Domain"
        value={filters.domain}
        options={DOMAINS}
        onChange={(domain) => onChange({ ...filters, domain })}
      />
      {(filters.severity || filters.domain) && (
        <div className="flex items-end">
          <button
            onClick={() => onChange({ severity: "", domain: "" })}
            className="text-xs text-ink-black dark:text-canvas-cream hover:underline py-1.5"
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  );
}
