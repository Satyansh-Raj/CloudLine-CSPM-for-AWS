import type { ReactNode } from "react";
import { useState, useRef, useEffect } from "react";
import { NavLink } from "react-router-dom";
import { useAccount } from "@/hooks/useAccount";
import { createAccount } from "@/api/accounts";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: "grid" },
  { to: "/violations", label: "Violations", icon: "alert" },
  { to: "/resolved", label: "Resolved", icon: "resolved" },
  { to: "/inventory", label: "Inventory", icon: "inventory" },
  { to: "/compliance", label: "Compliance", icon: "shield" },
  { to: "/iam-graph", label: "IAM Graph", icon: "graph" },
  { to: "/trends", label: "Trends", icon: "chart" },
  { to: "/executive", label: "Executive", icon: "briefcase" },
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
};

export default function Sidebar() {
  const { selectedAccount, accounts, setSelectedAccount, refresh } =
    useAccount();

  const [popoverOpen, setPopoverOpen] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [accountName, setAccountName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [saving, setSaving] = useState(false);

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
    : "All Accounts";

  async function handleSave() {
    if (!accountName || !accountId || !roleArn) return;
    setSaving(true);
    try {
      await createAccount({
        account_name: accountName,
        account_id: accountId,
        role_arn: roleArn,
      });
      await refresh();
      setAccountName("");
      setAccountId("");
      setRoleArn("");
      setModalOpen(false);
    } finally {
      setSaving(false);
    }
  }

  return (
    <aside
      className="
      w-60 shrink-0 min-h-screen flex flex-col
      bg-white dark:bg-black
      border-r border-gray-100 dark:border-white/5
    "
    >
      {/* Brand */}
      <div className="px-5 py-5 border-b border-gray-100 dark:border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shrink-0">
            <svg
              className="w-4 h-4 text-white"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
            >
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold tracking-tight text-gray-900 dark:text-white leading-none">
              CloudLine
            </p>
            <p className="text-[10px] text-gray-400 dark:text-gray-600 mt-0.5">
              AWS Security
            </p>
          </div>
        </div>
      </div>

      {/* Account Switcher */}
      <div
        className="px-3 py-3 border-b border-gray-100 dark:border-white/5"
        ref={popoverRef}
      >
        <p className="px-2 mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-700">
          Account
        </p>
        <button
          type="button"
          aria-label="Switch account"
          onClick={() => setPopoverOpen((o) => !o)}
          className="w-full flex items-center justify-between px-2.5 py-2 text-[13px] font-medium rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white hover:border-blue-400 focus:ring-2 focus:ring-blue-500/30 outline-none cursor-pointer transition-colors"
        >
          <span className="truncate">{buttonLabel}</span>
          <svg
            className="w-3.5 h-3.5 ml-1.5 shrink-0 text-gray-400"
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
            className="absolute z-50 mt-1 w-52 rounded-xl border border-gray-200 dark:border-white/10 bg-white dark:bg-neutral-900 shadow-lg py-1"
          >
            <div
              role="option"
              aria-selected={selectedAccount === ""}
              onClick={() => {
                setSelectedAccount("");
                setPopoverOpen(false);
              }}
              className={`px-3 py-2 text-[13px] cursor-pointer flex items-center gap-2 hover:bg-gray-50 dark:hover:bg-white/5 ${
                selectedAccount === ""
                  ? "text-blue-600 dark:text-blue-400 font-medium"
                  : "text-gray-700 dark:text-gray-300"
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-gray-300 dark:bg-gray-600 shrink-0" />
              All Accounts
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
                className={`px-3 py-2 text-[13px] cursor-pointer hover:bg-gray-50 dark:hover:bg-white/5 ${
                  selectedAccount === a.account_id
                    ? "text-blue-600 dark:text-blue-400 font-medium"
                    : "text-gray-700 dark:text-gray-300"
                }`}
              >
                <p className="truncate">{a.account_name}</p>
                <p className="text-[11px] text-gray-400 dark:text-gray-600 truncate">
                  {a.account_id}
                </p>
              </div>
            ))}
            <div className="border-t border-gray-100 dark:border-white/5 mt-1 pt-1">
              <button
                type="button"
                onClick={() => {
                  setPopoverOpen(false);
                  setModalOpen(true);
                }}
                className="w-full text-left px-3 py-2 text-[13px] text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-500/10 font-medium"
              >
                + Add Account
              </button>
            </div>
          </div>
        )}

        {modalOpen && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setModalOpen(false);
            }}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-label="Add Account"
              className="w-80 rounded-2xl bg-white dark:bg-neutral-900 border border-gray-200 dark:border-white/10 shadow-2xl p-5"
            >
              <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
                Add Account
              </h2>
              <div className="space-y-3">
                <input
                  type="text"
                  placeholder="Account Name"
                  value={accountName}
                  onChange={(e) => setAccountName(e.target.value)}
                  className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
                />
                <input
                  type="text"
                  placeholder="Account ID"
                  value={accountId}
                  onChange={(e) => setAccountId(e.target.value)}
                  className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
                />
                <input
                  type="text"
                  placeholder="Role ARN"
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                  className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
                />
              </div>
              <div className="flex gap-2 mt-4 justify-end">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-3 py-1.5 text-[13px] rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/5"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSave}
                  disabled={saving || !accountName || !accountId || !roleArn}
                  className="px-3 py-1.5 text-[13px] rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {saving ? "Saving…" : "Save"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-700">
          Menu
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-150 ${
                isActive
                  ? "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-500/20"
                  : "text-gray-500 dark:text-gray-500 hover:bg-gray-50 dark:hover:bg-white/5 hover:text-gray-900 dark:hover:text-gray-200 border border-transparent"
              }`
            }
          >
            {({ isActive }) => (
              <>
                <span
                  className={
                    isActive
                      ? "text-blue-500 dark:text-blue-400"
                      : "text-gray-400 dark:text-gray-600 group-hover:text-gray-600 dark:group-hover:text-gray-400 transition-colors"
                  }
                >
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
        <p className="text-[10px] text-gray-300 dark:text-gray-800 px-2">
          v0.1.0
        </p>
      </div>
    </aside>
  );
}
