import { CustomSelect } from "@/components/shared";

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

function toLabel(v: string, allLabel: string): string {
  return v === ""
    ? allLabel
    : v.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export type { FilterValues };

export default function ViolationFilters({ filters, onChange }: Props) {
  return (
    <div className="flex flex-wrap gap-4">
      <div>
        <label className="block text-xs font-medium text-slate-gray mb-1">
          Severity
        </label>
        <CustomSelect
          value={filters.severity}
          onChange={(severity) => onChange({ ...filters, severity })}
          options={SEVERITIES.map((s) => ({ value: s, label: toLabel(s, "All") }))}
          aria-label="Select severity"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-slate-gray mb-1">
          Domain
        </label>
        <CustomSelect
          value={filters.domain}
          onChange={(domain) => onChange({ ...filters, domain })}
          options={DOMAINS.map((d) => ({ value: d, label: toLabel(d, "All") }))}
          aria-label="Select domain"
        />
      </div>
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
