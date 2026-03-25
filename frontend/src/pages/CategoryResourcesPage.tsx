import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useInventory } from "@/hooks/useInventory";
import { useRegion } from "@/hooks/useRegion";
import { ExposureBadge } from "@/components/inventory";
import type { Resource } from "@/types/inventory";

function capitalize(s: string): string {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 76
      ? "text-red-600 dark:text-red-400"
      : score >= 51
        ? "text-orange-600 dark:text-orange-400"
        : score >= 26
          ? "text-yellow-600 dark:text-yellow-400"
          : "text-green-600 dark:text-green-400";

  return (
    <span className={`text-sm font-bold tabular-nums ${color}`}>{score}</span>
  );
}

function ResourceRow({ resource }: { resource: Resource }) {
  return (
    <Link
      to="/inventory/detail"
      state={{ resource }}
      aria-label={resource.resource_name}
      className="flex items-center gap-3 px-4 py-3 hover:bg-gray-50
        dark:hover:bg-white/5 transition-colors rounded-xl group"
    >
      {/* Resource name */}
      <span
        className="flex-1 min-w-0 text-sm font-medium text-gray-900
          dark:text-white group-hover:text-blue-600
          dark:group-hover:text-blue-400 truncate"
      >
        {resource.resource_name}
      </span>

      {/* Service badge */}
      <span
        className="hidden sm:inline-flex items-center px-2 py-0.5 rounded
          text-xs font-medium bg-blue-50 dark:bg-blue-500/10
          text-blue-700 dark:text-blue-300 border border-blue-100
          dark:border-blue-500/20 whitespace-nowrap"
      >
        {resource.service}
      </span>

      {/* Exposure */}
      <ExposureBadge exposure={resource.exposure} />

      {/* Violation count */}
      <span
        className="hidden sm:block text-xs tabular-nums text-gray-500
          dark:text-gray-400 whitespace-nowrap"
      >
        {resource.violation_count}{" "}
        {resource.violation_count === 1 ? "violation" : "violations"}
      </span>

      {/* Risk score */}
      <RiskScore score={resource.risk_score} />
    </Link>
  );
}

export default function CategoryResourcesPage() {
  const { category = "" } = useParams<{ category: string }>();
  const [region, setRegion] = useState("");
  const { regions } = useRegion();
  const { data, isLoading, error } = useInventory({
    category,
    ...(region ? { region } : {}),
  });

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link
          to="/inventory"
          aria-label="Back to Inventory"
          className="inline-flex items-center gap-1.5 text-sm text-gray-500
            dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400
            transition-colors"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M15 19l-7-7 7-7"
            />
          </svg>
          Back to Inventory
        </Link>
      </div>

      <h2
        className="text-xl font-bold text-gray-900 dark:text-white
          tracking-tight"
      >
        {capitalize(category)}
      </h2>

      {/* Region filter */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-wrap items-end gap-4">
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

      {/* Loading skeleton */}
      {isLoading && (
        <div
          className="bg-white dark:bg-[#111] border border-gray-100
            dark:border-white/5 rounded-2xl p-6 shadow-sm animate-pulse
            space-y-3"
        >
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-10 bg-gray-100 dark:bg-white/5 rounded-xl"
            />
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div
          className="bg-red-50 dark:bg-red-500/5 border border-red-200
            dark:border-red-500/20 rounded-2xl p-5"
        >
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load resources:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !error && data && data.length === 0 && (
        <div
          className="bg-white dark:bg-[#111] border border-gray-100
            dark:border-white/5 rounded-2xl p-10 shadow-sm text-center"
        >
          <p className="text-sm text-gray-500 dark:text-gray-400">
            No {category} resources found
          </p>
        </div>
      )}

      {/* Resource list */}
      {!isLoading && !error && data && data.length > 0 && (
        <div
          className="bg-white dark:bg-[#111] border border-gray-100
            dark:border-white/5 rounded-2xl shadow-sm overflow-hidden"
        >
          {/* Column headers */}
          <div
            className="flex items-center gap-3 px-4 py-2 border-b
              border-gray-100 dark:border-white/5"
          >
            <span
              className="flex-1 text-[10px] uppercase tracking-widest
                font-semibold text-gray-400 dark:text-gray-600"
            >
              Resource
            </span>
            <span
              className="hidden sm:block text-[10px] uppercase
                tracking-widest font-semibold text-gray-400
                dark:text-gray-600"
            >
              Service
            </span>
            <span
              className="text-[10px] uppercase tracking-widest font-semibold
                text-gray-400 dark:text-gray-600"
            >
              Exposure
            </span>
            <span
              className="hidden sm:block text-[10px] uppercase
                tracking-widest font-semibold text-gray-400
                dark:text-gray-600 whitespace-nowrap"
            >
              Violations
            </span>
            <span
              className="text-[10px] uppercase tracking-widest font-semibold
                text-gray-400 dark:text-gray-600"
            >
              Risk
            </span>
          </div>

          {/* Rows */}
          <div className="divide-y divide-gray-50 dark:divide-white/5 p-1">
            {(data as Resource[]).map((r) => (
              <ResourceRow key={r.resource_id} resource={r} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
