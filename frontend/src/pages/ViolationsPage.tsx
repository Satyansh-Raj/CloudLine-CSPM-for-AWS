import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useViolations } from "@/hooks";
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

  const params = useMemo(() => {
    const p: Record<string, string> = { status: "alarm" };
    if (filters.severity) p.severity = filters.severity;
    if (filters.domain) p.domain = filters.domain;
    return p;
  }, [filters]);

  const { data, isLoading, error } = useViolations(params);

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
        Violations
      </h2>

      {/* Filters */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-4 shadow-sm">
        <ViolationFilters filters={filters} onChange={setFilters} />
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
            navigate(
              toViolationPath(v.check_id, v.resource),
              { state: { violation: v } },
            )
          }
        />
      )}
    </div>
  );
}
