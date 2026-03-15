import { useNavigate } from "react-router-dom";
import { useViolations } from "@/hooks";
import { ViolationsTable } from "@/components/violations";
import { toViolationPath } from "@/utils/violationUrl";
import type { Violation } from "@/types";

export default function ResolvedIssuesPage() {
  const navigate = useNavigate();
  const { data, isLoading, error } = useViolations({ status: "ok" });

  return (
    <div>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
              Resolved Issues
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-500 mt-0.5">
              Violations that currently pass their security checks
            </p>
          </div>
          {data && data.length > 0 && (
            <span className="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-full bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 border border-green-100 dark:border-green-500/20">
              {data.length} resolved
            </span>
          )}
        </div>

        {/* Loading */}
        {isLoading && (
          <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-8 shadow-sm animate-pulse space-y-3">
            {Array.from({ length: 6 }).map((_, i) => (
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
              Failed to load resolved issues:{" "}
              {(error as { message?: string }).message ?? "Unknown error"}
            </p>
          </div>
        )}

        {/* Empty state */}
        {!isLoading && !error && data && data.length === 0 && (
          <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-12 text-center shadow-sm">
            <div className="w-12 h-12 rounded-2xl bg-green-50 dark:bg-green-500/10 flex items-center justify-center mx-auto mb-3">
              <svg
                className="w-6 h-6 text-green-500 dark:text-green-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>
            <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
              No resolved issues yet
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-600 mt-1">
              Violations that pass their checks will appear here.
            </p>
          </div>
        )}

        {/* Table */}
        {data && data.length > 0 && (
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
    </div>
  );
}
