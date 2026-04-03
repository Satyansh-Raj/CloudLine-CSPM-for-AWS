import { Link } from "react-router-dom";
import { useInventorySummary } from "@/hooks/useInventory";
import { useAccount } from "@/hooks/useAccount";

/* ---------- category icons ---------- */

/* All 10 categories have custom PNG artwork in
   public/icons/, served at build time from /icons/. */
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

/* ---------- page ---------- */

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
      {/* Heading + total stat */}
      <div className="flex items-baseline justify-between">
        <h2
          className="text-xl font-bold text-gray-900
            dark:text-white tracking-tight"
        >
          Inventory
        </h2>
        {summary && (
          <span
            className="text-sm text-gray-500
              dark:text-gray-400"
          >
            <span
              className="font-semibold text-gray-900
                dark:text-white"
            >
              {summary.total}
            </span>{" "}
            total resources
          </span>
        )}
      </div>

      {/* Loading skeleton */}
      {isLoading && (
        <div
          className="grid grid-cols-2 sm:grid-cols-3
            lg:grid-cols-5 gap-4 animate-pulse"
        >
          {Array.from({ length: 10 }).map((_, i) => (
            <div
              key={i}
              className="aspect-square rounded-2xl
                bg-gray-100 dark:bg-white/5 border
                border-gray-100 dark:border-white/5"
            />
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div
          className="bg-red-50 dark:bg-red-500/5
            border border-red-200
            dark:border-red-500/20 rounded-xl p-5"
        >
          <p
            className="text-sm text-red-700
              dark:text-red-400"
          >
            Failed to load inventory:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Empty state */}
      {summary && summary.total === 0 && (
        <div
          className="flex items-center justify-center
            py-20 text-gray-400 dark:text-gray-600
            text-sm"
        >
          No resources found
        </div>
      )}

      {/* Category card grid — square cards */}
      {summary && summary.total > 0 && (
        <div
          className="grid grid-cols-2 sm:grid-cols-3
            lg:grid-cols-5 gap-4"
        >
          {Object.entries(summary.by_category)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([category, count]) => {
              const icon = CATEGORY_ICONS[category.toLowerCase()];
              return (
                <Link
                  key={category}
                  to={`/inventory/${category}`}
                  className="group aspect-square
                    flex flex-col items-center
                    justify-center gap-2
                    bg-white dark:bg-[#111]
                    border border-gray-100
                    dark:border-white/5
                    rounded-2xl p-3
                    shadow-sm hover:shadow-lg
                    hover:border-gray-200
                    dark:hover:border-white/10
                    transition-all duration-200
                    overflow-hidden"
                >
                  {/* Icon */}
                  <img
                    src={icon ?? "/icons/storage.png"}
                    alt={category}
                    loading="eager"
                    decoding="async"
                    className="w-full max-h-[60%]
                      object-contain drop-shadow-md
                      flex-shrink-0"
                  />

                  {/* Category name */}
                  <span
                    className="text-xs font-medium
                      text-gray-500
                      dark:text-gray-400
                      leading-tight text-center"
                  >
                    {capitalize(category)}
                  </span>

                  {/* Resource count */}
                  <span
                    className="text-2xl font-bold
                      text-gray-900 dark:text-white
                      leading-none"
                  >
                    {count}
                  </span>
                </Link>
              );
            })}
        </div>
      )}
    </div>
  );
}
