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
import type { Resource } from "@/types/inventory";
import ExposureBadge from "./ExposureBadge";

interface Props {
  data: Resource[];
}

const col = createColumnHelper<Resource>();

const columns = [
  col.accessor("resource_name", {
    header: "Resource",
    cell: (info) => (
      <div>
        <span className="text-sm font-medium text-gray-900 dark:text-white">
          {info.getValue()}
        </span>
        <span className="block text-[10px] font-mono text-gray-400 dark:text-gray-500 truncate max-w-[220px]"
          title={info.row.original.resource_id}
        >
          {info.row.original.resource_id}
        </span>
      </div>
    ),
  }),
  col.accessor("resource_type", {
    header: "Type",
    cell: (info) => (
      <span className="text-sm capitalize">
        {info.getValue().replace(/_/g, " ")}
      </span>
    ),
  }),
  col.accessor("technology_category", {
    header: "Category",
    cell: (info) => (
      <span className="text-sm capitalize">
        {info.getValue()}
      </span>
    ),
  }),
  col.accessor("exposure", {
    header: "Exposure",
    cell: (info) => (
      <ExposureBadge exposure={info.getValue()} />
    ),
  }),
  col.accessor("violation_count", {
    header: "Violations",
    cell: (info) => {
      const v = info.getValue();
      return (
        <span
          className={
            v > 0
              ? "text-sm font-semibold text-red-600 dark:text-red-400"
              : "text-sm text-gray-400 dark:text-gray-500"
          }
        >
          {v}
        </span>
      );
    },
  }),
  col.accessor("risk_score", {
    header: "Risk",
    cell: (info) => {
      const s = info.getValue();
      let cls =
        "text-sm text-gray-400 dark:text-gray-500";
      if (s >= 80)
        cls =
          "text-sm font-bold text-red-600"
          + " dark:text-red-400";
      else if (s >= 50)
        cls =
          "text-sm font-semibold text-orange-600"
          + " dark:text-orange-400";
      else if (s > 0)
        cls =
          "text-sm text-yellow-600"
          + " dark:text-yellow-400";
      return <span className={cls}>{s}</span>;
    },
  }),
  col.accessor("tags", {
    header: "Tags",
    enableSorting: false,
    cell: (info) => {
      const tags = info.getValue();
      const entries = Object.entries(tags);
      if (entries.length === 0) {
        return (
          <span className="text-xs text-gray-400 dark:text-gray-600">
            —
          </span>
        );
      }
      return (
        <div className="flex flex-wrap gap-1 max-w-[200px]">
          {entries.slice(0, 3).map(([k, v]) => (
            <span
              key={k}
              className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300 truncate max-w-[180px]"
              title={`${k}=${v}`}
            >
              {k}={v}
            </span>
          ))}
          {entries.length > 3 && (
            <span className="text-[10px] text-gray-400 dark:text-gray-500">
              +{entries.length - 3}
            </span>
          )}
        </div>
      );
    },
  }),
];

export default function InventoryTable({
  data,
}: Props) {
  const [sorting, setSorting] =
    useState<SortingState>([]);

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: { pageSize: 15 },
    },
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
                    onClick={
                      header.column
                        .getToggleSortingHandler()
                    }
                  >
                    <div className="flex items-center gap-1">
                      {flexRender(
                        header.column.columnDef
                          .header,
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
            {table.getRowModel().rows.length ===
            0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-8 text-center text-sm text-gray-500 dark:text-gray-400"
                >
                  No resources found.
                </td>
              </tr>
            ) : (
              table
                .getRowModel()
                .rows.map((row) => (
                  <tr
                    key={row.id}
                    className="hover:bg-gray-50 dark:hover:bg-white/[0.04] transition-colors"
                  >
                    {row
                      .getVisibleCells()
                      .map((cell) => (
                        <td
                          key={cell.id}
                          className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100"
                        >
                          {flexRender(
                            cell.column.columnDef
                              .cell,
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
            {table.getState().pagination
              .pageIndex + 1}{" "}
            of {table.getPageCount()} (
            {data.length} total)
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => table.previousPage()}
              disabled={
                !table.getCanPreviousPage()
              }
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
