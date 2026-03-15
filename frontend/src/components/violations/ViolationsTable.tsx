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
import {
  SeverityBadge,
  StatusBadge,
} from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";

interface Props {
  data: Violation[];
  onRowClick: (violation: Violation) => void;
}

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
    cell: (info) => (
      <SeverityBadge severity={info.getValue()} />
    ),
  }),
  col.accessor("status", {
    header: "Status",
    cell: (info) => (
      <StatusBadge status={info.getValue()} />
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

export default function ViolationsTable({
  data,
  onRowClick,
}: Props) {
  const [sorting, setSorting] = useState<SortingState>([]);

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
      <div className="overflow-x-auto rounded-2xl border border-gray-100 dark:border-white/5">
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
                      }[
                        header.column.getIsSorted() as string
                      ] ?? null}
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
                  No violations found.
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="hover:bg-gray-50 dark:hover:bg-white/[0.04] cursor-pointer transition-colors"
                  onClick={() => onRowClick(row.original)}
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
            Page{" "}
            {table.getState().pagination.pageIndex + 1}{" "}
            of {table.getPageCount()} ({data.length}{" "}
            total)
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
  );
}
