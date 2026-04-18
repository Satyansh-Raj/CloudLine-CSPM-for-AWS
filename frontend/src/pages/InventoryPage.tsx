import { Link } from "react-router-dom";
import { useInventorySummary } from "@/hooks/useInventory";
import { useAccount } from "@/hooks/useAccount";
import {
  AccountBadge,
  EyebrowLabel,
  GhostHeadline,
} from "@/components/shared";

const CATEGORY_ICONS: Record<string, string> = {
  backup: "/icons/backup.png",
  compute: "/icons/compute.png",
  containers: "/icons/containers.png",
  database: "/icons/database.png",
  encryption: "/icons/encryption.png",
  identity: "/icons/identity.png",
  monitoring: "/icons/monitoring.png",
  network: "/icons/network.png",
  serverless: "/icons/serverless.png",
  storage: "/icons/storage.png",
};

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export default function InventoryPage() {
  const { selectedAccount } = useAccount();
  const accountId = selectedAccount || undefined;
  const {
    data: summary,
    isLoading,
    error,
  } = useInventorySummary(undefined, accountId);

  return (
    <div className="space-y-6">
      {/* Heading */}
      <div className="relative flex items-baseline justify-between">
        <GhostHeadline>INV</GhostHeadline>
        <div className="flex items-baseline gap-3">
          <div>
            <EyebrowLabel>Resource Catalogue</EyebrowLabel>
            <h2 className="text-xl font-bold text-ink-black dark:text-canvas-cream tracking-tight">
              Inventory
            </h2>
          </div>
          <AccountBadge />
        </div>
        {summary && (
          <span className="text-sm text-slate-gray">
            <span className="font-semibold text-ink-black dark:text-canvas-cream">
              {summary.total}
            </span>{" "}
            total resources
          </span>
        )}
      </div>

      {/* Loading skeleton */}
      {isLoading && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 animate-pulse">
          {Array.from({ length: 10 }).map((_, i) => (
            <div
              key={i}
              className="aspect-square rounded-hero bg-ghost-cream dark:bg-white/5 border border-ghost-cream dark:border-white/5"
            />
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-hero p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load inventory:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Empty state */}
      {summary && summary.total === 0 && (
        <div className="flex items-center justify-center py-20 text-slate-gray text-sm">
          No resources found
        </div>
      )}

      {/* Category card grid */}
      {summary && summary.total > 0 && (
        <div className="relative">
          {/* Orbital arc decoration — desktop only */}
          <svg
            aria-hidden="true"
            className="hidden lg:block absolute inset-0 w-full h-full pointer-events-none select-none"
            preserveAspectRatio="none"
          >
            <ellipse
              cx="50%"
              cy="50%"
              rx="45%"
              ry="40%"
              fill="none"
              stroke="#F37338"
              strokeWidth="1"
              strokeDasharray="6 8"
              opacity="0.25"
            />
          </svg>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 relative">
            {Object.entries(summary.by_category)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([category, count]) => {
                const icon = CATEGORY_ICONS[category.toLowerCase()];
                return (
                  <Link
                    key={category}
                    to={`/inventory/${category}`}
                    className="group flex flex-col items-center justify-center gap-3 bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1 hover:shadow-elev-2 hover:border-ink-black/20 dark:hover:border-white/15 transition-all duration-200 overflow-hidden"
                  >
                    {/* Circular portrait icon */}
                    <div className="w-16 h-16 rounded-full overflow-hidden bg-ghost-cream dark:bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:scale-105 transition-transform duration-200">
                      <img
                        src={icon ?? "/icons/storage.png"}
                        alt={category}
                        loading="eager"
                        decoding="async"
                        className="w-10 h-10 object-contain drop-shadow-sm"
                      />
                    </div>

                    {/* Eyebrow-style category name */}
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray text-center leading-tight">
                      {capitalize(category)}
                    </span>

                    {/* Resource count */}
                    <span className="text-2xl font-black text-ink-black dark:text-canvas-cream leading-none">
                      {count}
                    </span>
                  </Link>
                );
              })}
          </div>
        </div>
      )}
    </div>
  );
}
