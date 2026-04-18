import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useInventory } from "@/hooks/useInventory";
import { useRegion } from "@/hooks/useRegion";
import { ExposureBadge } from "@/components/inventory";
import { EyebrowLabel } from "@/components/shared";
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
      className="flex items-center gap-3 px-4 py-3 hover:bg-canvas-cream dark:hover:bg-white/5 transition-colors rounded-xl group"
    >
      <span className="flex-1 min-w-0 text-sm font-medium text-ink-black dark:text-canvas-cream group-hover:text-link-blue dark:group-hover:text-link-blue truncate">
        {resource.resource_name}
      </span>

      <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-pill text-xs font-medium bg-ghost-cream dark:bg-white/5 text-slate-gray whitespace-nowrap">
        {resource.service}
      </span>

      <ExposureBadge exposure={resource.exposure} />

      <span className="hidden sm:block text-xs tabular-nums text-slate-gray whitespace-nowrap">
        {resource.violation_count}{" "}
        {resource.violation_count === 1 ? "violation" : "violations"}
      </span>

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
          className="inline-flex items-center gap-1.5 text-sm text-slate-gray hover:text-ink-black dark:hover:text-canvas-cream transition-colors"
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

      <div>
        <EyebrowLabel>Category</EyebrowLabel>
        <h2 className="text-xl font-bold text-ink-black dark:text-canvas-cream tracking-tight mt-0.5">
          {capitalize(category)}
        </h2>
      </div>

      {/* Region filter */}
      <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-4 shadow-elev-1">
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-gray mb-1">
              Region
            </label>
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="block w-full rounded-pill border border-ghost-cream dark:border-white/10 bg-canvas-cream dark:bg-ink-black text-sm text-ink-black dark:text-canvas-cream px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink-black"
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
        <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-6 shadow-elev-1 animate-pulse space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-10 bg-ghost-cream dark:bg-white/5 rounded-xl"
            />
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-hero p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load resources:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !error && data && data.length === 0 && (
        <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-10 shadow-elev-1 text-center">
          <p className="text-sm text-slate-gray">
            No {category} resources found
          </p>
        </div>
      )}

      {/* Resource list */}
      {!isLoading && !error && data && data.length > 0 && (
        <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero shadow-elev-1 overflow-hidden">
          {/* Column headers */}
          <div className="flex items-center gap-3 px-4 py-2 border-b border-ghost-cream dark:border-white/5">
            <span className="flex-1 text-[10px] uppercase tracking-widest font-semibold text-slate-gray/70">
              Resource
            </span>
            <span className="hidden sm:block text-[10px] uppercase tracking-widest font-semibold text-slate-gray/70">
              Service
            </span>
            <span className="text-[10px] uppercase tracking-widest font-semibold text-slate-gray/70">
              Exposure
            </span>
            <span className="hidden sm:block text-[10px] uppercase tracking-widest font-semibold text-slate-gray/70 whitespace-nowrap">
              Violations
            </span>
            <span className="text-[10px] uppercase tracking-widest font-semibold text-slate-gray/70">
              Risk
            </span>
          </div>

          {/* Rows */}
          <div className="divide-y divide-ghost-cream dark:divide-white/5 p-1">
            {(data as Resource[]).map((r) => (
              <ResourceRow key={r.resource_id} resource={r} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
