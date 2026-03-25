import { Link } from "react-router-dom";
import { useInventorySummary } from "@/hooks/useInventory";

/* ---------- category icon SVGs ---------- */

function StorageIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <ellipse cx="12" cy="7" rx="9" ry="3" />
      <path d="M3 7v5c0 1.657 4.03 3 9 3s9-1.343 9-3V7" />
      <path d="M3 12v5c0 1.657 4.03 3 9 3s9-1.343 9-3v-5" />
    </svg>
  );
}

function ComputeIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <rect x="2" y="4" width="20" height="6" rx="1" />
      <rect x="2" y="14" width="20" height="6" rx="1" />
      <line x1="6" y1="7" x2="6" y2="7.01" />
      <line x1="10" y1="7" x2="14" y2="7" />
      <line x1="6" y1="17" x2="6" y2="17.01" />
      <line x1="10" y1="17" x2="14" y2="17" />
    </svg>
  );
}

function DatabaseIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14c0 1.657 4.03 3 9 3s9-1.343 9-3V5" />
      <path d="M3 12c0 1.657 4.03 3 9 3s9-1.343 9-3" />
    </svg>
  );
}

function NetworkIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3c-3 3-4.5 5.5-4.5 9s1.5 6 4.5 9" />
      <path d="M12 3c3 3 4.5 5.5 4.5 9s-1.5 6-4.5 9" />
    </svg>
  );
}

function IdentityIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <circle cx="9" cy="7" r="3" />
      <path d="M3 21v-2a5 5 0 0 1 5-5h2" />
      <circle cx="17" cy="16" r="2" />
      <path d="M21 21l-1.5-1.5" />
      <path d="M19 14l-2 2" />
    </svg>
  );
}

function ServerlessIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <path d="M13 2L4.09 12.26a1 1 0 0 0 .74 1.67H11l-1 8 8.91-10.26a1 1 0 0 0-.74-1.67H13l1-8z" />
    </svg>
  );
}

function EncryptionIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
      <circle cx="12" cy="16" r="1" fill="currentColor" />
    </svg>
  );
}

function MonitoringIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <polyline points="3 12 6 9 9 14 12 8 15 13 18 10 21 12" />
    </svg>
  );
}

function BackupIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <circle cx="12" cy="12" r="9" />
      <polyline points="12 7 12 12 15 15" />
      <path d="M7.5 4.5A9 9 0 0 0 4.5 9" />
      <path d="M4 5l.5 4h4" />
    </svg>
  );
}

function ContainersIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <rect x="2" y="14" width="9" height="8" rx="1" />
      <rect x="13" y="14" width="9" height="8" rx="1" />
      <rect x="7" y="5" width="10" height="8" rx="1" />
    </svg>
  );
}

function DefaultIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
      className="w-5 h-5">
      <line x1="4" y1="7" x2="20" y2="7" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <line x1="4" y1="17" x2="20" y2="17" />
    </svg>
  );
}

/* ---------- category config ---------- */

type CategoryConfig = {
  icon: React.ReactNode;
  badgeBg: string;
  badgeText: string;
};

function getCategoryConfig(category: string): CategoryConfig {
  const key = category.toLowerCase();
  const configs: Record<string, CategoryConfig> = {
    storage: {
      icon: <StorageIcon />,
      badgeBg: "bg-blue-100 dark:bg-blue-500/20",
      badgeText: "text-blue-600 dark:text-blue-400",
    },
    compute: {
      icon: <ComputeIcon />,
      badgeBg: "bg-orange-100 dark:bg-orange-500/20",
      badgeText: "text-orange-600 dark:text-orange-400",
    },
    database: {
      icon: <DatabaseIcon />,
      badgeBg: "bg-purple-100 dark:bg-purple-500/20",
      badgeText: "text-purple-600 dark:text-purple-400",
    },
    network: {
      icon: <NetworkIcon />,
      badgeBg: "bg-cyan-100 dark:bg-cyan-500/20",
      badgeText: "text-cyan-600 dark:text-cyan-400",
    },
    identity: {
      icon: <IdentityIcon />,
      badgeBg: "bg-yellow-100 dark:bg-yellow-500/20",
      badgeText: "text-yellow-600 dark:text-yellow-400",
    },
    serverless: {
      icon: <ServerlessIcon />,
      badgeBg: "bg-emerald-100 dark:bg-emerald-500/20",
      badgeText: "text-emerald-600 dark:text-emerald-400",
    },
    encryption: {
      icon: <EncryptionIcon />,
      badgeBg: "bg-pink-100 dark:bg-pink-500/20",
      badgeText: "text-pink-600 dark:text-pink-400",
    },
    monitoring: {
      icon: <MonitoringIcon />,
      badgeBg: "bg-indigo-100 dark:bg-indigo-500/20",
      badgeText: "text-indigo-600 dark:text-indigo-400",
    },
    backup: {
      icon: <BackupIcon />,
      badgeBg: "bg-teal-100 dark:bg-teal-500/20",
      badgeText: "text-teal-600 dark:text-teal-400",
    },
    containers: {
      icon: <ContainersIcon />,
      badgeBg: "bg-slate-100 dark:bg-slate-500/20",
      badgeText: "text-slate-600 dark:text-slate-400",
    },
  };
  return configs[key] ?? {
    icon: <DefaultIcon />,
    badgeBg: "bg-gray-100 dark:bg-white/10",
    badgeText: "text-gray-500 dark:text-gray-400",
  };
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/* ---------- page ---------- */

export default function InventoryPage() {
  const { data: summary, isLoading, error } = useInventorySummary();

  return (
    <div className="space-y-6">
      {/* Heading + total stat */}
      <div className="flex items-baseline justify-between">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white
          tracking-tight">
          Inventory
        </h2>
        {summary && (
          <span className="text-sm text-gray-500 dark:text-gray-400">
            <span className="font-semibold text-gray-900 dark:text-white">
              {summary.total}
            </span>{" "}
            total resources
          </span>
        )}
      </div>

      {/* Loading skeleton */}
      {isLoading && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4
          animate-pulse">
          {Array.from({ length: 8 }).map((_, i) => (
            <div
              key={i}
              className="h-24 bg-gray-100 dark:bg-white/5 rounded-xl border
                border-gray-100 dark:border-white/5"
            />
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200
          dark:border-red-500/20 rounded-xl p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load inventory:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Empty state */}
      {summary && summary.total === 0 && (
        <div className="flex items-center justify-center py-20 text-gray-400
          dark:text-gray-600 text-sm">
          No resources found
        </div>
      )}

      {/* Category card grid */}
      {summary && summary.total > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
          {Object.entries(summary.by_category)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([category, count]) => {
              const cfg = getCategoryConfig(category);
              return (
                <Link
                  key={category}
                  to={`/inventory/${category}`}
                  className="group flex flex-col gap-3 bg-white dark:bg-[#111]
                    border border-gray-100 dark:border-white/5 rounded-xl p-4
                    shadow-sm hover:shadow-md transition-shadow duration-150"
                >
                  {/* Icon badge */}
                  <span className={`inline-flex items-center justify-center
                    w-9 h-9 rounded-lg ${cfg.badgeBg} ${cfg.badgeText}
                    flex-shrink-0`}>
                    {cfg.icon}
                  </span>

                  {/* Category name */}
                  <span className="text-xs font-medium text-gray-500
                    dark:text-gray-400 leading-tight">
                    {capitalize(category)}
                  </span>

                  {/* Resource count */}
                  <span className="text-2xl font-bold text-gray-900
                    dark:text-white leading-none">
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
