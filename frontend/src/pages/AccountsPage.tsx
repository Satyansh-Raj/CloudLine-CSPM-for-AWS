import { useState } from "react";
import { useAccount } from "@/hooks/useAccount";
import {
  createAccount,
  deleteAccount,
} from "@/api/accounts";

export default function AccountsPage() {
  const { accounts, isLoading, refresh } =
    useAccount();

  const [name, setName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleAdd() {
    if (!name || !accountId || !roleArn) return;
    setSubmitting(true);
    try {
      await createAccount({
        account_name: name,
        account_id: accountId,
        role_arn: roleArn,
      });
      setName("");
      setAccountId("");
      setRoleArn("");
      refresh();
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRemove(id: string) {
    await deleteAccount(id);
    refresh();
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
        Accounts
      </h2>

      {/* Add account form */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
        <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-600 mb-3">
          Add Target Account
        </p>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[140px]">
            <input
              type="text"
              placeholder="Account Name"
              value={name}
              onChange={(e) =>
                setName(e.target.value)
              }
              className="w-full px-3 py-2 text-sm rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white placeholder:text-gray-400 dark:placeholder:text-gray-600 focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400 outline-none"
            />
          </div>
          <div className="flex-1 min-w-[140px]">
            <input
              type="text"
              placeholder="Account ID"
              value={accountId}
              onChange={(e) =>
                setAccountId(e.target.value)
              }
              className="w-full px-3 py-2 text-sm rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white placeholder:text-gray-400 dark:placeholder:text-gray-600 focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400 outline-none"
            />
          </div>
          <div className="flex-[2] min-w-[200px]">
            <input
              type="text"
              placeholder="Role ARN"
              value={roleArn}
              onChange={(e) =>
                setRoleArn(e.target.value)
              }
              className="w-full px-3 py-2 text-sm rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white placeholder:text-gray-400 dark:placeholder:text-gray-600 focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400 outline-none"
            />
          </div>
          <button
            onClick={handleAdd}
            disabled={
              submitting
              || !name
              || !accountId
              || !roleArn
            }
            className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Add Account
          </button>
        </div>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-8 shadow-sm animate-pulse space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-16 bg-gray-100 dark:bg-white/5 rounded-xl"
            />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!isLoading && accounts.length === 0 && (
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-8 text-center shadow-sm">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            No target accounts configured. Add an
            account above to enable cross-account
            scanning.
          </p>
        </div>
      )}

      {/* Account list */}
      {accounts.length > 0 && (
        <div className="space-y-3">
          {accounts.map((a) => (
            <div
              key={a.account_id}
              className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">
                      {a.account_name}
                    </p>
                    <span className="text-xs font-mono text-gray-400 dark:text-gray-500">
                      {a.account_id}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-gray-400 dark:text-gray-600 truncate">
                    {a.role_arn}
                  </p>
                  <div className="flex items-center gap-4 mt-2">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] uppercase tracking-wider text-gray-400 dark:text-gray-600">
                        Regions:
                      </span>
                      {a.regions.map((r) => (
                        <span
                          key={r}
                          className="text-xs px-1.5 py-0.5 rounded bg-gray-50 dark:bg-white/5 text-gray-600 dark:text-gray-400"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] uppercase tracking-wider text-gray-400 dark:text-gray-600">
                        Last scanned:
                      </span>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {a.last_scanned
                          ? new Date(
                              a.last_scanned,
                            ).toLocaleString()
                          : "Never"}
                      </span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={() =>
                    handleRemove(a.account_id)
                  }
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
