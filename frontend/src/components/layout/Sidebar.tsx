import type { ReactNode } from "react";
import { useState, useRef, useEffect } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAccount } from "@/hooks/useAccount";
import { usePermission } from "@/hooks/usePermission";
import { triggerScan } from "@/api/scans";
import type { TargetAccount } from "@/types/account";

function formatRelativeTime(iso: string | null): string {
  if (!iso) return "Never scanned";
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHrs = Math.floor(diffMins / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  const diffDays = Math.floor(diffHrs / 24);
  return `${diffDays}d ago`;
}

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: "grid" },
  { to: "/violations", label: "Violations", icon: "alert" },
  { to: "/resolved", label: "Resolved", icon: "resolved" },
  { to: "/inventory", label: "Inventory", icon: "inventory" },
  { to: "/compliance", label: "Compliance", icon: "shield" },
  { to: "/iam-graph", label: "IAM Graph", icon: "graph" },
  { to: "/trends", label: "Trends", icon: "chart" },

  { to: "/policies", label: "Policies", icon: "policy" },
];

function GridIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <rect x="3" y="3" width="7" height="7" rx="1.5" strokeWidth="1.8" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" strokeWidth="1.8" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" strokeWidth="1.8" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" strokeWidth="1.8" />
    </svg>
  );
}
function AlertIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M12 9v4m0 3.5h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
      />
    </svg>
  );
}
function ChartIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M3 17l4-5 4 3 4-6 4 4"
      />
      <path strokeLinecap="round" strokeWidth="1.8" d="M3 21h18" />
    </svg>
  );
}
function BriefcaseIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M20 7H4a2 2 0 00-2 2v10a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2z"
      />
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"
      />
    </svg>
  );
}
function PolicyIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
      />
    </svg>
  );
}
function GraphIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <circle cx="5" cy="12" r="2" strokeWidth="1.8" />
      <circle cx="19" cy="5" r="2" strokeWidth="1.8" />
      <circle cx="19" cy="19" r="2" strokeWidth="1.8" />
      <path strokeLinecap="round" strokeWidth="1.8" d="M7 11l10-5M7 13l10 5" />
    </svg>
  );
}
function InventoryIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
      />
    </svg>
  );
}
function ResolvedIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M12 2l7 4v5c0 5-3.5 9.7-7 11-3.5-1.3-7-6-7-11V6l7-4z"
      />
    </svg>
  );
}
function AccountsIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0H5m14 0h2m-16 0H3m5-12h.01M12 8h.01M12 12h.01M12 16h.01M8 12h.01M8 16h.01"
      />
    </svg>
  );
}
function UsersIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8zM23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"
      />
    </svg>
  );
}

const iconMap: Record<string, ReactNode> = {
  grid: <GridIcon />,
  alert: <AlertIcon />,
  resolved: <ResolvedIcon />,
  inventory: <InventoryIcon />,
  graph: <GraphIcon />,
  chart: <ChartIcon />,
  briefcase: <BriefcaseIcon />,
  policy: <PolicyIcon />,
  accounts: <AccountsIcon />,
  shield: <ShieldIcon />,
  users: <UsersIcon />,
};

export default function Sidebar() {
  const { selectedAccount, accounts, setSelectedAccount, refresh } =
    useAccount();
  const { can } = usePermission();
  const navigate = useNavigate();

  const [popoverOpen, setPopoverOpen] = useState(false);

  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!popoverOpen) return;
    function handleClick(e: MouseEvent) {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(e.target as Node)
      ) {
        setPopoverOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [popoverOpen]);

  const activeAccount = accounts.find((a) => a.account_id === selectedAccount);
  const buttonLabel = activeAccount
    ? activeAccount.account_name
    : "Root Account";

  async function handleScanNow(acct: TargetAccount) {
    try {
      await triggerScan(acct.account_id);
    } finally {
      await refresh();
    }
  }

  return (
    <aside
      className="
      w-60 shrink-0 min-h-screen flex flex-col
      bg-lifted-cream dark:bg-ink-black
      border-r border-ghost-cream dark:border-white/5
    "
    >
      {/* Brand */}
      <div className="px-5 py-5 border-b border-ghost-cream dark:border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-full bg-ink-black dark:bg-canvas-cream flex items-center justify-center shrink-0">
            <svg
              className="w-4 h-4 text-canvas-cream dark:text-ink-black"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
            >
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold tracking-tight text-ink-black dark:text-canvas-cream leading-none">
              CloudLine
            </p>
            <p className="text-[10px] text-slate-gray mt-0.5">AWS Security</p>
          </div>
        </div>
      </div>

      {/* Account Switcher */}
      <div
        className="px-3 py-3 border-b border-ghost-cream dark:border-white/5"
        ref={popoverRef}
      >
        <p className="px-2 mb-1.5 text-[10px] font-semibold uppercase tracking-eyebrow text-slate-gray">
          Account
        </p>
        <button
          type="button"
          aria-label="Switch account"
          onClick={() => setPopoverOpen((o) => !o)}
          className="w-full flex items-center justify-between px-2.5 py-2 text-[13px] font-medium rounded-pill border border-dust-taupe dark:border-white/10 bg-canvas-cream dark:bg-ink-black text-ink-black dark:text-canvas-cream hover:border-ink-black dark:hover:border-canvas-cream/50 focus:ring-2 focus:ring-ink-black/20 outline-none cursor-pointer transition-colors"
        >
          <span className="truncate">{buttonLabel}</span>
          <svg
            className="w-3.5 h-3.5 ml-1.5 shrink-0 text-slate-gray"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </button>

        {popoverOpen && (
          <div
            role="listbox"
            aria-label="Select account"
            className="absolute z-50 mt-1 w-52 rounded-hero border border-dust-taupe dark:border-white/10 bg-lifted-cream dark:bg-ink-black shadow-elev-1 py-1 overflow-hidden"
          >
            <div
              role="option"
              aria-selected={selectedAccount === ""}
              onClick={() => {
                setSelectedAccount("");
                setPopoverOpen(false);
              }}
              className={`px-6 py-2 text-[13px] cursor-pointer flex items-center gap-2 hover:bg-ghost-cream dark:hover:bg-white/5 ${
                selectedAccount === ""
                  ? "bg-ghost-cream dark:bg-white/5 text-ink-black dark:text-canvas-cream font-medium"
                  : "text-slate-gray dark:text-ghost-cream"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${selectedAccount === "" ? "bg-ink-black dark:bg-canvas-cream" : "bg-dust-taupe dark:bg-slate-gray"}`}
              />
              Root Account
              {selectedAccount === "" && (
                <span className="ml-auto text-[11px]">✓</span>
              )}
            </div>
            {accounts.map((a) => (
              <div
                key={a.account_id}
                role="option"
                aria-selected={selectedAccount === a.account_id}
                onClick={() => {
                  setSelectedAccount(a.account_id);
                  setPopoverOpen(false);
                }}
                className={`px-6 py-2 text-[13px] cursor-pointer hover:bg-ghost-cream dark:hover:bg-white/5 ${
                  selectedAccount === a.account_id
                    ? "bg-ghost-cream dark:bg-white/5 text-ink-black dark:text-canvas-cream font-medium"
                    : "text-slate-gray dark:text-ghost-cream"
                }`}
              >
                <div className="flex items-center justify-between">
                  <p className="truncate">{a.account_name}</p>
                  {selectedAccount === a.account_id && (
                    <span className="text-[11px] shrink-0">✓</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-gray truncate">
                  {a.account_id}
                </p>
                <div className="flex items-center justify-between mt-0.5">
                  <p className="text-[10px] text-slate-gray">
                    {formatRelativeTime(a.last_scanned)}
                  </p>
                  <button
                    type="button"
                    aria-label={`Scan now ${a.account_name}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleScanNow(a);
                    }}
                    className="text-[10px] px-1.5 py-0.5 rounded-btn bg-ghost-cream dark:bg-white/10 text-ink-black dark:text-canvas-cream hover:bg-dust-taupe dark:hover:bg-white/20 font-medium"
                  >
                    Scan Now
                  </button>
                </div>
              </div>
            ))}
            <div className="border-t border-ghost-cream dark:border-white/5 mt-1 pt-1">
              <button
                type="button"
                onClick={() => {
                  setPopoverOpen(false);
                  navigate("/accounts");
                }}
                className="w-full text-left px-10 py-2 text-[13px] text-ink-black dark:text-canvas-cream hover:bg-ghost-cream dark:hover:bg-white/5 font-medium"
              >
                + Add Account
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-eyebrow text-slate-gray">
          Menu
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3 py-2.5 rounded-pill text-[13px] font-medium transition-all duration-150 ${
                isActive
                  ? "bg-ink-black text-canvas-cream border border-transparent dark:bg-canvas-cream dark:text-ink-black"
                  : "text-slate-gray dark:text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5 hover:text-ink-black dark:hover:text-canvas-cream border border-transparent"
              }`
            }
          >
            {({ isActive }) => (
              <>
                <span
                  className={
                    isActive
                      ? "text-canvas-cream dark:text-ink-black"
                      : "text-slate-gray dark:text-slate-gray group-hover:text-ink-black dark:group-hover:text-canvas-cream transition-colors"
                  }
                >
                  {iconMap[item.icon]}
                </span>
                {item.label}
                {isActive && (
                  <span className="ml-auto w-1.5 h-1.5 rounded-full bg-canvas-cream dark:bg-ink-black" />
                )}
              </>
            )}
          </NavLink>
        ))}
        {can("manage_users") && (
          <NavLink
            to="/users"
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3 py-2.5 rounded-pill text-[13px] font-medium transition-all duration-150 ${
                isActive
                  ? "bg-ink-black text-canvas-cream border border-transparent dark:bg-canvas-cream dark:text-ink-black"
                  : "text-slate-gray dark:text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5 hover:text-ink-black dark:hover:text-canvas-cream border border-transparent"
              }`
            }
          >
            {({ isActive }) => (
              <>
                <span
                  className={
                    isActive
                      ? "text-canvas-cream dark:text-ink-black"
                      : "text-slate-gray dark:text-slate-gray group-hover:text-ink-black dark:group-hover:text-canvas-cream transition-colors"
                  }
                >
                  {iconMap["users"]}
                </span>
                User Management
                {isActive && (
                  <span className="ml-auto w-1.5 h-1.5 rounded-full bg-canvas-cream dark:bg-ink-black" />
                )}
              </>
            )}
          </NavLink>
        )}
      </nav>

      {/* Version */}
      <div className="px-3 py-4 border-t border-ghost-cream dark:border-white/5">
        <p className="text-[10px] text-dust-taupe dark:text-slate-gray px-2">
          v0.4.13
        </p>
      </div>
    </aside>
  );
}
