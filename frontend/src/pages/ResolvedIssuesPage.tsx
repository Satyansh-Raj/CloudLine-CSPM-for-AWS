import React, { useState } from "react";
import { useViolations } from "@/hooks/useViolations";
import { useRegion } from "@/hooks/useRegion";
import { useAccount } from "@/hooks/useAccount";
import IssueLifecycleChart from "@/components/IssueLifecycleChart";
import type { Violation } from "@/types";

/* ---- helpers ---- */

const SEV_PILL: Record<string, string> = {
  critical: "bg-red-100 dark:bg-red-500/20 " + "text-red-600 dark:text-red-400",
  high:
    "bg-orange-100 dark:bg-orange-500/20 " +
    "text-orange-600 dark:text-orange-400",
  medium:
    "bg-yellow-100 dark:bg-yellow-500/20 " +
    "text-yellow-600 dark:text-yellow-400",
  low:
    "bg-green-100 dark:bg-green-500/20 " + "text-green-600 dark:text-green-400",
};

function formatDate(iso?: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function shortArn(arn: string): string {
  const parts = arn.split(":");
  return parts[parts.length - 1] || arn;
}

function rowKey(v: Violation, idx: number): string {
  return `${v.check_id}-${v.resource}-${idx}`;
}

/* ---- sub-components ---- */

function CheckIcon() {
  return (
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
  );
}

interface ChevronProps {
  expanded: boolean;
  testId: string;
}

function Chevron({ expanded, testId }: ChevronProps) {
  return (
    <span
      data-testid={testId}
      className={
        "text-gray-400 dark:text-gray-600 " +
        "transition-transform text-xs select-none " +
        (expanded ? "rotate-90 inline-block" : "inline-block")
      }
    >
      {expanded ? "▾" : "▸"}
    </span>
  );
}

/* ---- main page ---- */

export default function ResolvedIssuesPage() {
  const { selectedRegion, regions, setSelectedRegion } = useRegion();
  const { selectedAccount } = useAccount();

  const { data, isLoading, error } = useViolations({
    status: "ok",
    region: selectedRegion || undefined,
    account_id: selectedAccount || undefined,
  } as Parameters<typeof useViolations>[0]);

  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  function handleRowClick(key: string) {
    setExpandedRow((prev) => (prev === key ? null : key));
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
            Resolved Issues
          </h2>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
            Violations that currently pass their security checks
          </p>
        </div>

        <div className="flex items-center gap-3">
          {data && data.length > 0 && (
            <span className="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-full bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 border border-green-100 dark:border-green-500/20">
              {data.length} resolved
            </span>
          )}

          {/* Region selector */}
          <label className="flex items-center gap-2">
            <span className="sr-only">Region</span>
            <select
              aria-label="Region"
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              className="text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-700 dark:text-gray-300 px-3 py-1.5 outline-none focus:ring-2 focus:ring-blue-500/30"
            >
              <option value="">All Regions</option>
              {regions.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
        </div>
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
            <CheckIcon />
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
      {!isLoading && !error && data && data.length > 0 && (
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table
              className="w-full text-sm"
              data-testid="resolved-issues-table"
            >
              <thead>
                <tr className="border-b border-gray-100 dark:border-white/5 bg-gray-50 dark:bg-white/[0.02]">
                  <th className="text-left py-3 px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider w-6"></th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Resource
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Check ID
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Previous Status
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Resolved At
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Domain
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((v: Violation, idx: number) => {
                  const key = rowKey(v, idx);
                  const isExpanded = expandedRow === key;
                  return (
                    <React.Fragment key={key}>
                      <tr
                        data-testid="expandable-row"
                        onClick={() => handleRowClick(key)}
                        className={
                          "border-b border-gray-50 " +
                          "dark:border-white/5 last:border-0 " +
                          "cursor-pointer " +
                          "hover:bg-gray-50 " +
                          "dark:hover:bg-white/5 " +
                          "transition-colors"
                        }
                      >
                        {/* Chevron */}
                        <td className="py-3 px-3">
                          <Chevron
                            expanded={isExpanded}
                            testId={`chevron-${idx}`}
                          />
                        </td>

                        {/* Resource */}
                        <td className="py-3 px-4 max-w-[200px]">
                          <span
                            className="block text-xs font-mono text-gray-700 dark:text-gray-300 truncate"
                            title={v.resource}
                          >
                            {shortArn(v.resource)}
                          </span>
                        </td>

                        {/* Check ID */}
                        <td className="py-3 px-4">
                          <span className="text-xs font-mono text-gray-600 dark:text-gray-400">
                            {v.check_id}
                          </span>
                        </td>

                        {/* Previous Status */}
                        <td className="py-3 px-4">
                          <span
                            data-testid={`prev-status-${idx}`}
                            className="inline-flex items-center text-xs font-medium px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-500/20 text-red-600 dark:text-red-400"
                          >
                            {v.previous_status ?? "alarm"}
                          </span>
                        </td>

                        {/* Resolved At */}
                        <td
                          className="py-3 px-4 text-xs text-gray-500 dark:text-gray-500"
                          data-testid={`resolved-at-${idx}`}
                        >
                          {formatDate(v.resolved_at)}
                        </td>

                        {/* Domain */}
                        <td className="py-3 px-4 text-xs capitalize text-gray-600 dark:text-gray-400">
                          {v.domain.replace(/_/g, " ")}
                        </td>

                        {/* Severity */}
                        <td className="py-3 px-4">
                          <span
                            className={
                              "inline-flex items-center text-xs " +
                              "font-medium px-2 py-0.5 rounded-full " +
                              "capitalize " +
                              (SEV_PILL[v.severity] ?? SEV_PILL.low)
                            }
                          >
                            {v.severity}
                          </span>
                        </td>
                      </tr>

                      {/* Expanded lifecycle row */}
                      {isExpanded && (
                        <tr
                          key={`${key}-expanded`}
                          data-testid="expanded-content"
                        >
                          <td
                            colSpan={7}
                            className="bg-gray-50/50 dark:bg-white/[0.02] border-b border-gray-100 dark:border-white/5"
                          >
                            <IssueLifecycleChart
                              firstDetected={v.first_detected}
                              resolvedAt={v.resolved_at}
                              previousStatus={v.previous_status}
                            />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
