import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from "@tanstack/react-table";
import { useViolations } from "@/hooks/useViolations";
import { useRegion } from "@/hooks/useRegion";
import { useAccount } from "@/hooks/useAccount";
import { toResolvedPath } from "@/utils/violationUrl";
import { SeverityBadge, StatusBadge } from "@/components/shared";
import { ViolationFilters, type FilterValues } from "@/components/violations";
import { getCheckName } from "@/constants/checkNames";
import type { Violation } from "@/types";

/* ---- helpers ---- */

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

/* ---- table columns ---- */

const col = createColumnHelper<Violation>();

const columns = [
  col.accessor("check_id", {
    header: "Issue",
    cell: (info) => (
      <div>
        <span className="text-sm font-medium text-gray-900 dark:text-white">
          {getCheckName(info.getValue())}
        </span>
        <span className="block text-[10px] font-mono text-gray-400 dark:text-gray-500">
          {info.getValue()}
        </span>
      </div>
    ),
  }),
  col.accessor("resource", {
    header: "Resource",
    cell: (info) => (
      <span
        className="font-mono text-xs truncate block max-w-[200px]"
        title={info.getValue()}
      >
        {info.getValue() || "—"}
      </span>
    ),
  }),
  col.accessor("severity", {
    header: "Severity",
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
  }),
  col.accessor((row) => row.previous_status ?? "alarm", {
    id: "previous_status",
    header: "Previous Status",
    cell: (info) => <StatusBadge status={info.getValue()} />,
  }),
  col.accessor("resolved_at", {
    header: "Resolved At",
    cell: (info) => (
      <span className="text-xs text-gray-500 dark:text-gray-500">
        {formatDate(info.getValue())}
      </span>
    ),
  }),
  col.accessor("domain", {
    header: "Domain",
    cell: (info) => (
      <span className="text-sm capitalize">
        {info.getValue().replace(/_/g, " ")}
      </span>
    ),
  }),
];

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

/* ---- main page ---- */

export default function ResolvedIssuesPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { regions } = useRegion();
  const { selectedAccount } = useAccount();
  const [sorting, setSorting] = useState<SortingState>([
    { id: "resolved_at", desc: true },
  ]);

  const filters: FilterValues = {
    severity: searchParams.get("severity") ?? "",
    domain: searchParams.get("domain") ?? "",
  };
  const selectedRegion = searchParams.get("region") ?? "";

  function setFilters(next: FilterValues) {
    setSearchParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (next.severity) p.set("severity", next.severity);
        else p.delete("severity");
        if (next.domain) p.set("domain", next.domain);
        else p.delete("domain");
        return p;
      },
      { replace: true },
    );
  }

  function setSelectedRegion(r: string) {
    setSearchParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (r) p.set("region", r);
        else p.delete("region");
        return p;
      },
      { replace: true },
    );
  }

  const params = useMemo(() => {
    const p: Record<string, string> = { status: "ok" };
    if (filters.severity) p.severity = filters.severity;
    if (filters.domain) p.domain = filters.domain;
    if (selectedRegion) p.region = selectedRegion;
    if (selectedAccount) p.account_id = selectedAccount;
    return p;
  }, [filters, selectedRegion, selectedAccount]);

  const { data, isLoading, error } = useViolations(
    params as Parameters<typeof useViolations>[0],
  );

  const table = useReactTable({
    data: data ?? [],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 15 } },
  });

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

        {data && data.length > 0 && (
          <span className="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-full bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 border border-green-100 dark:border-green-500/20">
            {data.length} resolved
          </span>
        )}
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-wrap items-end gap-4">
          <ViolationFilters filters={filters} onChange={setFilters} />
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Region
            </label>
            <select
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
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
        <div>
          <div
            className="overflow-x-auto rounded-2xl border border-gray-100 dark:border-white/5"
            data-testid="resolved-issues-table"
          >
            <table className="min-w-full divide-y divide-gray-100 dark:divide-white/5">
              <thead className="bg-gray-50 dark:bg-white/[0.03]">
                {table.getHeaderGroups().map((hg) => (
                  <tr key={hg.id}>
                    {hg.headers.map((header) => (
                      <th
                        key={header.id}
                        className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer select-none hover:bg-gray-100 dark:hover:bg-white/5"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        <div className="flex items-center gap-1">
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                          {{
                            asc: " \u2191",
                            desc: " \u2193",
                          }[header.column.getIsSorted() as string] ?? null}
                        </div>
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody className="bg-white dark:bg-[#111] divide-y divide-gray-100 dark:divide-white/5">
                {table.getRowModel().rows.length === 0 ? (
                  <tr>
                    <td
                      colSpan={columns.length}
                      className="px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400"
                    >
                      No resolved issues found.
                    </td>
                  </tr>
                ) : (
                  table.getRowModel().rows.map((row) => (
                    <tr
                      key={row.id}
                      data-testid="resolved-row"
                      className="hover:bg-gray-50 dark:hover:bg-white/[0.04] cursor-pointer transition-colors"
                      onClick={() =>
                        navigate(
                          toResolvedPath(
                            row.original.check_id,
                            row.original.resource,
                          ),
                          {
                            state: {
                              violation: row.original,
                            },
                          },
                        )
                      }
                    >
                      {row.getVisibleCells().map((cell) => (
                        <td
                          key={cell.id}
                          className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100"
                        >
                          {flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext(),
                          )}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {table.getPageCount() > 1 && (
            <div className="flex items-center justify-between mt-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Page {table.getState().pagination.pageIndex + 1} of{" "}
                {table.getPageCount()} ({data.length} total)
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => table.previousPage()}
                  disabled={!table.getCanPreviousPage()}
                  className="px-3 py-1.5 text-sm rounded-md border border-gray-200 dark:border-white/10 text-gray-700 dark:text-gray-300 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-white/5 transition-colors"
                >
                  Previous
                </button>
                <button
                  onClick={() => table.nextPage()}
                  disabled={!table.getCanNextPage()}
                  className="px-3 py-1.5 text-sm rounded-md border border-gray-200 dark:border-white/10 text-gray-700 dark:text-gray-300 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-white/5 transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
