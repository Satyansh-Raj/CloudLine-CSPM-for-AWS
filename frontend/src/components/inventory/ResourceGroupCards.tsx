import { useMemo } from "react";
import type { Resource } from "@/types/inventory";
import ExposureBadge from "./ExposureBadge";

interface Props {
  data: Resource[];
  onCategoryClick?: (category: string) => void;
}

function CategoryIcon({ category }: { category: string }) {
  const svgProps = {
    className: "w-4 h-4",
    fill: "none" as const,
    stroke: "currentColor",
    strokeWidth: 2,
    viewBox: "0 0 24 24",
  };
  const lc = {
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
  switch (category) {
    case "storage":
      return (
        <svg {...svgProps}>
          <ellipse cx="12" cy="6" rx="8" ry="3" {...lc} />
          <path d="M4 6v4c0 1.66 3.58 3 8 3s8-1.34 8-3V6" {...lc} />
          <path d="M4 10v4c0 1.66 3.58 3 8 3s8-1.34 8-3v-4" {...lc} />
          <path d="M4 14v4c0 1.66 3.58 3 8 3s8-1.34 8-3v-4" {...lc} />
        </svg>
      );
    case "compute":
      return (
        <svg {...svgProps}>
          <rect x="2" y="4" width="20" height="16" rx="2" {...lc} />
          <line x1="6" y1="9" x2="18" y2="9" {...lc} />
          <line x1="6" y1="12" x2="18" y2="12" {...lc} />
          <line x1="6" y1="15" x2="14" y2="15" {...lc} />
        </svg>
      );
    case "database":
      return (
        <svg {...svgProps}>
          <ellipse cx="12" cy="5" rx="8" ry="2.5" {...lc} />
          <path d="M4 5v5c0 1.38 3.58 2.5 8 2.5s8-1.12 8-2.5V5" {...lc} />
          <path d="M4 10v5c0 1.38 3.58 2.5 8 2.5s8-1.12 8-2.5v-5" {...lc} />
          <line x1="12" y1="7.5" x2="12" y2="20" {...lc} />
        </svg>
      );
    case "network":
      return (
        <svg {...svgProps}>
          <circle cx="12" cy="12" r="9" {...lc} />
          <path d="M3 12h18" {...lc} />
          <path d="M12 3c-2.5 3-4 5.7-4 9s1.5 6 4 9" {...lc} />
          <path d="M12 3c2.5 3 4 5.7 4 9s-1.5 6-4 9" {...lc} />
        </svg>
      );
    case "identity":
      return (
        <svg {...svgProps}>
          <circle cx="10" cy="7" r="4" {...lc} />
          <path d="M2 21v-2a4 4 0 0 1 4-4h8" {...lc} />
          <path d="M18 15l-2 2 2 2" {...lc} />
          <path d="M22 17h-6" {...lc} />
        </svg>
      );
    case "serverless":
      return (
        <svg {...svgProps}>
          <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" {...lc} />
        </svg>
      );
    case "encryption":
      return (
        <svg {...svgProps}>
          <rect x="5" y="11" width="14" height="10" rx="2" {...lc} />
          <path d="M8 11V7a4 4 0 0 1 8 0v4" {...lc} />
          <circle cx="12" cy="16" r="1" fill="currentColor" />
        </svg>
      );
    case "monitoring":
      return (
        <svg {...svgProps}>
          <path d="M22 12h-4l-3 9L9 3l-3 9H2" {...lc} />
        </svg>
      );
    case "backup":
      return (
        <svg {...svgProps}>
          <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" {...lc} />
          <path d="M3 3v5h5" {...lc} />
          <path d="M12 7v5l4 2" {...lc} />
        </svg>
      );
    case "containers":
      return (
        <svg {...svgProps}>
          <rect x="2" y="14" width="9" height="8" rx="1" {...lc} />
          <rect x="13" y="14" width="9" height="8" rx="1" {...lc} />
          <rect x="7" y="5" width="10" height="8" rx="1" {...lc} />
        </svg>
      );
    default:
      return (
        <svg {...svgProps}>
          <path d="M4 6h16M4 12h16M4 18h16" {...lc} />
        </svg>
      );
  }
}

const CATEGORY_ICON_BG: Record<string, string> = {
  storage: "bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300",
  compute:
    "bg-orange-50 text-orange-700 dark:bg-orange-900/20 dark:text-orange-300",
  database:
    "bg-purple-50 text-purple-700 dark:bg-purple-900/20 dark:text-purple-300",
  network: "bg-cyan-50 text-cyan-700 dark:bg-cyan-900/20 dark:text-cyan-300",
  identity:
    "bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300",
  serverless:
    "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300",
  encryption:
    "bg-pink-50 text-pink-700 dark:bg-pink-900/20 dark:text-pink-300",
  monitoring:
    "bg-indigo-50 text-indigo-700 dark:bg-indigo-900/20 dark:text-indigo-300",
  backup: "bg-teal-50 text-teal-700 dark:bg-teal-900/20 dark:text-teal-300",
  containers:
    "bg-slate-50 text-slate-700 dark:bg-slate-900/20 dark:text-slate-300",
};

interface CategoryGroup {
  category: string;
  resources: Resource[];
  totalViolations: number;
  totalRisk: number;
}

function riskClass(score: number): string {
  if (score >= 80) return "font-bold text-red-600 dark:text-red-400";
  if (score >= 50) return "font-semibold text-orange-600 dark:text-orange-400";
  if (score > 0) return "text-yellow-600 dark:text-yellow-400";
  return "text-slate-gray/50";
}

export default function ResourceGroupCards({ data, onCategoryClick }: Props) {
  const groups = useMemo<CategoryGroup[]>(() => {
    const map = new Map<string, Resource[]>();
    for (const r of data) {
      const key = r.technology_category;
      const list = map.get(key) ?? [];
      list.push(r);
      map.set(key, list);
    }
    return [...map.entries()]
      .map(([category, resources]) => ({
        category,
        resources,
        totalViolations: resources.reduce(
          (sum, r) => sum + r.violation_count,
          0,
        ),
        totalRisk: Math.max(...resources.map((r) => r.risk_score), 0),
      }))
      .sort((a, b) => b.totalViolations - a.totalViolations);
  }, [data]);

  if (data.length === 0) {
    return (
      <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-8 text-center shadow-elev-1">
        <p className="text-sm text-slate-gray">
          No resources found. Run a scan to populate the inventory.
        </p>
      </div>
    );
  }

  const headerContent = (g: CategoryGroup) => (
    <>
      <div className="flex items-center gap-2.5">
        <span
          className={`inline-flex items-center justify-center w-8 h-8 rounded-full text-xs ${CATEGORY_ICON_BG[g.category] ?? "bg-ghost-cream text-slate-gray"}`}
        >
          <CategoryIcon category={g.category} />
        </span>
        <span className="text-sm font-semibold text-ink-black dark:text-canvas-cream capitalize">
          {g.category}
        </span>
        <span className="text-xs text-slate-gray">{g.resources.length}</span>
      </div>

      <div className="flex items-center gap-3">
        {g.totalViolations > 0 ? (
          <span
            data-testid="category-violations"
            className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-400"
          >
            <svg
              className="w-3.5 h-3.5"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z"
              />
            </svg>
            {g.totalViolations}
          </span>
        ) : (
          <span
            data-testid="category-violations"
            className="text-xs text-slate-gray/50"
          >
            {g.totalViolations}
          </span>
        )}
      </div>
    </>
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {groups.map((g) => (
        <div
          key={g.category}
          data-testid="category-card"
          className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero shadow-elev-1 overflow-hidden"
        >
          {/* Card header */}
          {onCategoryClick ? (
            <button
              role="button"
              onClick={() => onCategoryClick(g.category)}
              className="w-full flex items-center justify-between px-5 py-3 border-b border-ghost-cream dark:border-white/5 text-left hover:bg-canvas-cream dark:hover:bg-white/5 transition-colors"
            >
              {headerContent(g)}
            </button>
          ) : (
            <div className="flex items-center justify-between px-5 py-3 border-b border-ghost-cream dark:border-white/5">
              {headerContent(g)}
            </div>
          )}

          {/* Resource rows */}
          <div className="divide-y divide-ghost-cream dark:divide-white/[0.03]">
            {g.resources.map((r) => (
              <div
                key={r.resource_id}
                data-testid="resource-row"
                className="flex items-center justify-between px-5 py-2.5 hover:bg-canvas-cream dark:hover:bg-white/[0.03] transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-ink-black dark:text-canvas-cream truncate">
                      {r.resource_name}
                    </p>
                    <p className="text-[10px] font-mono text-slate-gray/60 truncate max-w-[260px]">
                      {r.resource_id}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[10px] font-medium uppercase tracking-wider text-slate-gray bg-ghost-cream dark:bg-white/5 px-1.5 py-0.5 rounded-pill">
                    {r.service}
                  </span>
                  <ExposureBadge exposure={r.exposure} />
                  {r.violation_count > 0 ? (
                    <span className="text-xs font-semibold text-red-600 dark:text-red-400 min-w-[16px] text-right">
                      {r.violation_count}
                    </span>
                  ) : (
                    <span className="text-xs text-slate-gray/30 min-w-[16px] text-right">
                      0
                    </span>
                  )}
                  <span
                    data-testid="risk-score"
                    className={`text-xs min-w-[24px] text-right ${riskClass(r.risk_score)}`}
                  >
                    {r.risk_score}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
