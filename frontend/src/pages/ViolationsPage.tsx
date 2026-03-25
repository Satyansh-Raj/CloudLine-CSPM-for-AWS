import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useViolations } from "@/hooks";
import { useRegion } from "@/hooks/useRegion";
import {
  ViolationsTable,
  ViolationFilters,
  type FilterValues,
} from "@/components/violations";
import { toViolationPath } from "@/utils/violationUrl";
import type { Violation } from "@/types";

export default function ViolationsPage() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<FilterValues>({
    severity: "",
    domain: "",
  });
  const [region, setRegion] = useState("");
  const { regions } = useRegion();

  const params = useMemo(() => {
    const p: Record<string, string> = { status: "alarm" };
    if (filters.severity) p.severity = filters.severity;
    if (filters.domain) p.domain = filters.domain;
    if (region) p.region = region;
    return p;
  }, [filters, region]);

  const { data, isLoading, error } = useViolations(params);

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
        Violations
      </h2>

      {/* Filters */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-wrap items-end gap-4">
          <ViolationFilters filters={filters} onChange={setFilters} />
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Region
            </label>
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="block w-full rounded-md border border-gray-200 dark:border-white/10 bg-white dark:bg-[#1a1a1a] text-sm text-gray-900 dark:text-gray-100 px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary-500"
              aria-label="Select region"
            >
              <option value="">All Regions</option>
              {regions.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-8 shadow-sm animate-pulse space-y-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <div
              key={i}
              className="h-10 bg-gray-100 dark:bg-white/5 rounded-xl"
            />
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-2xl p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load violations:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Table */}
      {data && (
        <ViolationsTable
          data={data}
          onRowClick={(v: Violation) =>
            navigate(toViolationPath(v.check_id, v.resource), {
              state: { violation: v },
            })
          }
        />
      )}
    </div>
  );
}
