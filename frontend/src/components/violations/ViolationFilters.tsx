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
      <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="block w-full rounded-md border border-gray-200 dark:border-white/10 bg-white dark:bg-[#1a1a1a] text-sm text-gray-900 dark:text-gray-100 px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary-500"
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
            className="text-xs text-primary-600 dark:text-primary-400 hover:underline py-1.5"
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  );
}
