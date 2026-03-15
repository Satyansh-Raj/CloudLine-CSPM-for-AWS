import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: "grid" },
  { to: "/violations", label: "Violations", icon: "alert" },
  { to: "/resolved", label: "Resolved", icon: "resolved" },
  { to: "/iam-graph", label: "IAM Graph", icon: "graph" },
  { to: "/trends", label: "Trends", icon: "chart" },
  { to: "/executive", label: "Executive", icon: "briefcase" },
  { to: "/policies", label: "Policies", icon: "policy" },
];

function GridIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <rect x="3" y="3" width="7" height="7" rx="1.5" strokeWidth="1.8" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" strokeWidth="1.8" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" strokeWidth="1.8" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" strokeWidth="1.8" />
    </svg>
  );
}
function AlertIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8"
        d="M12 9v4m0 3.5h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
    </svg>
  );
}
function ChartIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8"
        d="M3 17l4-5 4 3 4-6 4 4" />
      <path strokeLinecap="round" strokeWidth="1.8" d="M3 21h18" />
    </svg>
  );
}
function BriefcaseIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8"
        d="M20 7H4a2 2 0 00-2 2v10a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8"
        d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2" />
    </svg>
  );
}
function PolicyIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8"
        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  );
}
function GraphIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <circle cx="5" cy="12" r="2" strokeWidth="1.8" />
      <circle cx="19" cy="5" r="2" strokeWidth="1.8" />
      <circle cx="19" cy="19" r="2" strokeWidth="1.8" />
      <path strokeLinecap="round" strokeWidth="1.8" d="M7 11l10-5M7 13l10 5" />
    </svg>
  );
}
function ResolvedIcon() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8"
        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}
const iconMap: Record<string, ReactNode> = {
  grid: <GridIcon />,
  alert: <AlertIcon />,
  resolved: <ResolvedIcon />,
  graph: <GraphIcon />,
  chart: <ChartIcon />,
  briefcase: <BriefcaseIcon />,
  policy: <PolicyIcon />,
};

export default function Sidebar() {
  return (
    /*
     * Light: pure white sidebar with gray-100 resting text, gray-900 active.
     * Dark: pure #000 (black) sidebar, inverted.
     */
    <aside className="
      w-60 shrink-0 min-h-screen flex flex-col
      bg-white dark:bg-black
      border-r border-gray-100 dark:border-white/5
    ">
      {/* Brand */}
      <div className="px-5 py-5 border-b border-gray-100 dark:border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shrink-0">
            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold tracking-tight text-gray-900 dark:text-white leading-none">CloudLine</p>
            <p className="text-[10px] text-gray-400 dark:text-gray-600 mt-0.5">AWS Security</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-700">Menu</p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-150 ${isActive
                ? "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-500/20"
                : "text-gray-500 dark:text-gray-500 hover:bg-gray-50 dark:hover:bg-white/5 hover:text-gray-900 dark:hover:text-gray-200 border border-transparent"
              }`
            }
          >
            {({ isActive }) => (
              <>
                <span className={isActive ? "text-blue-500 dark:text-blue-400" : "text-gray-400 dark:text-gray-600 group-hover:text-gray-600 dark:group-hover:text-gray-400 transition-colors"}>
                  {iconMap[item.icon]}
                </span>
                {item.label}
                {isActive && (
                  <span className="ml-auto w-1.5 h-1.5 rounded-full bg-blue-500 dark:bg-blue-400" />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Version */}
      <div className="px-3 py-4 border-t border-gray-100 dark:border-white/5">
        <p className="text-[10px] text-gray-300 dark:text-gray-800 px-2">v0.1.0</p>
      </div>
    </aside>
  );
}
