import { useState } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from "@tanstack/react-table";
import type { Violation } from "@/types";
import { SeverityBadge, StatusBadge } from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";

interface Props {
  data: Violation[];
  onRowClick: (violation: Violation) => void;
}

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

const col = createColumnHelper<Violation>();

const columns = [
  col.accessor("check_id", {
    header: "Issue",
    cell: (info) => (
      <div>
        <span className="text-sm font-medium text-ink-black dark:text-canvas-cream">
          {getCheckName(info.getValue())}
        </span>
        <span className="block mt-0.5 text-[10px] font-mono text-slate-gray/70 dark:text-slate-gray/50">
          {info.getValue()}
        </span>
      </div>
    ),
  }),
  col.accessor("resource", {
    header: "Resource",
    cell: (info) => (
      <span
        className="font-mono text-xs truncate block max-w-[200px] text-ink-black dark:text-canvas-cream"
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
  col.accessor("status", {
    header: "Status",
    cell: (info) => <StatusBadge status={info.getValue()} />,
  }),
  col.accessor("domain", {
    header: "Domain",
    cell: (info) => (
      <span className="text-sm capitalize text-ink-black dark:text-canvas-cream">
        {info.getValue().replace(/_/g, " ")}
      </span>
    ),
  }),
  col.accessor("first_detected", {
    header: "Detected",
    sortingFn: "datetime",
    cell: (info) => (
      <span className="text-xs text-slate-gray">
        {formatDate(info.getValue())}
      </span>
    ),
  }),
];

export default function ViolationsTable({ data, onRowClick }: Props) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: "first_detected", desc: true },
  ]);

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 15 } },
  });

  return (
    <div>
      <div className="overflow-x-auto rounded-hero border border-ghost-cream dark:border-white/5">
        <table className="min-w-full divide-y divide-ghost-cream dark:divide-white/5">
          <thead className="bg-canvas-cream dark:bg-ink-black/30">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-10 py-3 text-left text-xs font-medium text-slate-gray uppercase tracking-wider cursor-pointer select-none hover:bg-ghost-cream dark:hover:bg-white/5"
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
          <tbody className="bg-lifted-cream dark:bg-ink-black divide-y divide-ghost-cream dark:divide-white/5">
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-8 text-center text-sm text-slate-gray"
                >
                  No violations found.
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="hover:bg-canvas-cream dark:hover:bg-white/[0.04] cursor-pointer transition-colors"
                  onClick={() => onRowClick(row.original)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="px-10 py-3 whitespace-nowrap text-sm text-ink-black dark:text-canvas-cream"
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
          <p className="text-sm text-slate-gray">
            Page {table.getState().pagination.pageIndex + 1} of{" "}
            {table.getPageCount()} ({data.length} total)
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="px-3 py-1.5 text-sm rounded-btn border border-ghost-cream dark:border-white/10 text-ink-black dark:text-canvas-cream disabled:opacity-40 hover:bg-ghost-cream dark:hover:bg-white/5 transition-colors"
            >
              Previous
            </button>
            <button
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="px-3 py-1.5 text-sm rounded-btn border border-ghost-cream dark:border-white/10 text-ink-black dark:text-canvas-cream disabled:opacity-40 hover:bg-ghost-cream dark:hover:bg-white/5 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
