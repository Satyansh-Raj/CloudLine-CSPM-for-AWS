import { useCallback, useEffect, useState } from "react";
import {
  listUsers,
  createUser,
  approveReset,
  listResetRequests,
  getLoginHistory,
  setUserPassword,
  deleteUser,
  assignUserAccounts,
  reactivateUser,
  purgeUser,
} from "@/api/users";
import type { ApiError } from "@/api/client";
import type {
  CreateUserRequest,
  LoginEvent,
  AssignUserAccountsRequest,
} from "@/api/users";
import { getAccounts } from "@/api/accounts";
import type { TargetAccount } from "@/types/account";
import type { User, UserRole } from "@/types/auth";
import EyebrowLabel from "@/components/shared/EyebrowLabel";
import CustomSelect from "@/components/shared/CustomSelect";

type Tab = "users" | "reset_requests";

const inputCls = [
  "w-full px-3 py-2 text-[13px]",
  "rounded-pill border border-ghost-cream dark:border-white/10",
  "bg-canvas-cream dark:bg-black",
  "text-ink-black dark:text-white",
  "outline-none focus:ring-2 focus:ring-ink-black/20",
].join(" ");

function InitialsAvatar({ name }: { name: string }) {
  const initials = name
    .split(" ")
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
  return (
    <span
      className={[
        "inline-flex items-center justify-center",
        "w-7 h-7 rounded-full shrink-0",
        "bg-ghost-cream dark:bg-white/10",
        "text-ink-black dark:text-gray-300",
        "text-[11px] font-semibold select-none",
      ].join(" ")}
      aria-hidden="true"
    >
      {initials}
    </span>
  );
}

function LoginHistoryModal({
  user,
  onClose,
}: {
  user: User;
  onClose: () => void;
}) {
  const [events, setEvents] = useState<LoginEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getLoginHistory(user.sk)
      .then(setEvents)
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, [user.sk]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Login history for ${user.full_name}`}
        className={[
          "w-[560px] max-h-[80vh] flex flex-col",
          "rounded-hero bg-lifted-cream dark:bg-[#1c1c1b]",
          "border border-ghost-cream dark:border-white/10 shadow-elev-2",
        ].join(" ")}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-ghost-cream dark:border-white/5">
          <div>
            <h2 className="text-sm font-semibold text-ink-black dark:text-white">
              Login History
            </h2>
            <p className="text-[12px] text-slate-gray dark:text-gray-400 mt-0.5">
              {user.full_name} · {user.email}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-gray hover:text-ink-black dark:hover:text-gray-200 text-lg leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-2">
          {loading ? (
            <div className="py-10 text-center text-[13px] text-slate-gray">
              Loading…
            </div>
          ) : events.length === 0 ? (
            <div className="py-10 text-center text-[13px] text-slate-gray">
              No login events recorded.
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="bg-canvas-cream dark:bg-white/[0.02]">
                  <th className="text-left px-3 py-2 font-medium text-slate-gray dark:text-gray-400">
                    Time
                  </th>
                  <th className="text-left px-3 py-2 font-medium text-slate-gray dark:text-gray-400">
                    IP
                  </th>
                  <th className="text-left px-3 py-2 font-medium text-slate-gray dark:text-gray-400">
                    Result
                  </th>
                  <th className="text-left px-3 py-2 font-medium text-slate-gray dark:text-gray-400">
                    User Agent
                  </th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => (
                  <tr
                    key={i}
                    className="border-t border-ghost-cream dark:border-white/5"
                  >
                    <td className="px-3 py-2 text-ink-black dark:text-gray-300 whitespace-nowrap">
                      {new Date(ev.ts).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-slate-gray dark:text-gray-400 font-mono">
                      {ev.ip}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`font-medium ${
                          ev.success
                            ? "text-green-600 dark:text-green-400"
                            : "text-red-500 dark:text-red-400"
                        }`}
                      >
                        {ev.success ? "Success" : "Failed"}
                      </span>
                    </td>
                    <td
                      className="px-3 py-2 text-slate-gray truncate max-w-[180px]"
                      title={ev.user_agent}
                    >
                      {ev.user_agent || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

function RoleBadge({ role }: { role: UserRole }) {
  const colors: Record<UserRole, string> = {
    admin:
      "bg-ink-black text-canvas-cream dark:bg-canvas-cream dark:text-ink-black",
    operator:
      "bg-ghost-cream text-ink-black dark:bg-white/10 dark:text-gray-200",
    viewer: "bg-ghost-cream text-slate-gray dark:bg-white/5 dark:text-gray-400",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded-pill text-[11px] font-medium capitalize ${colors[role]}`}
    >
      {role}
    </span>
  );
}

interface AddUserModalProps {
  onClose: () => void;
  onCreated: () => void;
}

function AddUserModal({ onClose, onCreated }: AddUserModalProps) {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      const req: CreateUserRequest = {
        email,
        full_name: fullName,
        role,
        initial_password: password,
      };
      await createUser(req);
      onCreated();
      onClose();
    } catch (err) {
      setError((err as ApiError).message ?? "Failed to create user.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Add User"
        className={[
          "w-96 rounded-hero p-5",
          "bg-lifted-cream dark:bg-[#1c1c1b]",
          "border border-ghost-cream dark:border-white/10 shadow-elev-2",
        ].join(" ")}
      >
        <h2 className="text-sm font-semibold text-ink-black dark:text-white mb-4">
          Add User
        </h2>

        {error && (
          <div
            role="alert"
            className="mb-3 px-3 py-2 rounded-hero bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            type="text"
            placeholder="Full Name"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            required
            className={inputCls}
          />
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className={inputCls}
          />
          <div>
            <input
              type="password"
              placeholder="Initial Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className={inputCls}
            />
            <p className="mt-1 text-[11px] text-slate-gray dark:text-gray-500">
              Min 12 chars · at least 1 digit · at least 1 symbol
            </p>
          </div>
          <CustomSelect
            value={role}
            onChange={(v) => setRole(v as UserRole)}
            options={[
              { value: "viewer", label: "Viewer" },
              { value: "operator", label: "Operator" },
              { value: "admin", label: "Admin" },
            ]}
            aria-label="Role"
          />
          <div className="flex gap-2 justify-end pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-[13px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-3 py-1.5 text-[13px] rounded-btn bg-ink-black text-canvas-cream font-medium hover:opacity-90 disabled:opacity-50"
            >
              {saving ? "Creating…" : "Create"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

interface SetPasswordModalProps {
  user: User;
  onClose: () => void;
}

function SetPasswordModal({ user, onClose }: SetPasswordModalProps) {
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (newPassword !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setSaving(true);
    try {
      await setUserPassword(user.sk, newPassword);
      setSuccess(true);
    } catch (err) {
      setError((err as ApiError).message ?? "Failed to set password.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Set password for ${user.full_name}`}
        className={[
          "w-96 rounded-hero p-5",
          "bg-lifted-cream dark:bg-[#1c1c1b]",
          "border border-ghost-cream dark:border-white/10 shadow-elev-2",
        ].join(" ")}
      >
        <h2 className="text-sm font-semibold text-ink-black dark:text-white mb-1">
          Set Password
        </h2>
        <p className="text-[12px] text-slate-gray dark:text-gray-400 mb-4">
          {user.full_name} · {user.email}
        </p>

        {error && (
          <div
            role="alert"
            className="mb-3 px-3 py-2 rounded-hero bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
          >
            {error}
          </div>
        )}

        {success ? (
          <div className="py-4 text-center">
            <p className="text-[13px] text-green-600 dark:text-green-400 font-medium mb-4">
              Password updated successfully.
            </p>
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 text-[13px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-300 hover:bg-ghost-cream dark:hover:bg-white/10"
            >
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-3">
            <div>
              <input
                type="password"
                placeholder="New Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className={inputCls}
              />
              <p className="mt-1 text-[11px] text-slate-gray dark:text-gray-500">
                Min 12 chars · at least 1 digit · at least 1 symbol
              </p>
            </div>
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              className={inputCls}
            />
            <div className="flex gap-2 justify-end pt-1">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 text-[13px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="px-3 py-1.5 text-[13px] rounded-btn bg-ink-black text-canvas-cream font-medium hover:opacity-90 disabled:opacity-50"
              >
                {saving ? "Saving…" : "Set Password"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function accountAccessLabel(user: User): string {
  if (user.role === "admin") return "—";
  if (user.all_accounts_access ?? true) return "All accounts";
  const count = user.allowed_account_ids?.length ?? 0;
  if (count === 0) return "No accounts";
  return `${count} account${count > 1 ? "s" : ""}`;
}

interface AssignAccountsModalProps {
  user: User;
  accounts: TargetAccount[];
  onClose: () => void;
  onSaved: () => void;
}

function AssignAccountsModal({
  user,
  accounts,
  onClose,
  onSaved,
}: AssignAccountsModalProps) {
  const [allAccess, setAllAccess] = useState(user.all_accounts_access ?? true);
  const [selectedIds, setSelectedIds] = useState<string[]>(
    user.allowed_account_ids ?? [],
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggleAccount(id: string) {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      const req: AssignUserAccountsRequest = {
        allowed_account_ids: allAccess ? [] : selectedIds,
        all_accounts_access: allAccess,
      };
      await assignUserAccounts(user.sk, req);
      onSaved();
      onClose();
    } catch (err) {
      setError((err as ApiError).message ?? "Failed to assign accounts.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Assign accounts for ${user.full_name}`}
        className={[
          "w-[480px] max-h-[80vh] flex flex-col",
          "rounded-hero bg-lifted-cream dark:bg-[#1c1c1b]",
          "border border-ghost-cream dark:border-white/10 shadow-elev-2",
        ].join(" ")}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-ghost-cream dark:border-white/5">
          <div>
            <h2 className="text-sm font-semibold text-ink-black dark:text-white">
              Assign Accounts
            </h2>
            <p className="text-[12px] text-slate-gray dark:text-gray-400 mt-0.5">
              {user.full_name} · {user.email}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-gray hover:text-ink-black dark:hover:text-gray-200 text-lg leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <form
          onSubmit={(e) => void handleSubmit(e)}
          className="overflow-y-auto flex-1 p-5 space-y-4"
        >
          {error && (
            <div
              role="alert"
              className="px-3 py-2 rounded-hero bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
            >
              {error}
            </div>
          )}

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={allAccess}
              onChange={(e) => setAllAccess(e.target.checked)}
              className="w-4 h-4 accent-ink-black"
              aria-label="All accounts"
            />
            <span className="text-[13px] font-medium text-ink-black dark:text-white">
              All accounts
            </span>
          </label>

          {accounts.length > 0 && (
            <div className="space-y-2 border-t border-ghost-cream dark:border-white/5 pt-3">
              <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-500">
                Specific accounts
              </p>
              {accounts.map((acc) => (
                <label
                  key={acc.account_id}
                  className="flex items-center gap-2 cursor-pointer select-none"
                >
                  <input
                    type="checkbox"
                    checked={selectedIds.includes(acc.account_id)}
                    disabled={allAccess}
                    onChange={() => toggleAccount(acc.account_id)}
                    className="w-4 h-4 accent-ink-black disabled:opacity-40"
                    aria-label={`${acc.account_name} (${acc.account_id})`}
                  />
                  <span
                    className={`text-[13px] ${allAccess ? "text-slate-gray dark:text-gray-600" : "text-ink-black dark:text-gray-200"}`}
                  >
                    {acc.account_name}
                    <span className="ml-1 text-slate-gray dark:text-gray-500 font-mono text-[11px]">
                      ({acc.account_id})
                    </span>
                  </span>
                </label>
              ))}
            </div>
          )}

          <div className="flex gap-2 justify-end pt-2 border-t border-ghost-cream dark:border-white/5">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-[13px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-3 py-1.5 text-[13px] rounded-btn bg-ink-black text-canvas-cream font-medium hover:opacity-90 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function UserManagementPage() {
  const [tab, setTab] = useState<Tab>("users");
  const [users, setUsers] = useState<User[]>([]);
  const [resets, setResets] = useState<User[]>([]);
  const [availableAccounts, setAvailableAccounts] = useState<TargetAccount[]>(
    [],
  );
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [historyUser, setHistoryUser] = useState<User | null>(null);
  const [passwordUser, setPasswordUser] = useState<User | null>(null);
  const [assignAccountsUser, setAssignAccountsUser] = useState<User | null>(
    null,
  );
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const [us, rs, accs] = await Promise.all([
        listUsers(),
        listResetRequests(),
        getAccounts(),
      ]);
      setUsers(us);
      setResets(rs);
      setAvailableAccounts(accs);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchUsers();
  }, [fetchUsers]);

  async function handleApproveReset(userId: string) {
    setDeleteError(null);
    try {
      await approveReset(userId);
      await fetchUsers();
    } catch (err) {
      setDeleteError(
        (err as { message?: string }).message ?? "Failed to approve reset.",
      );
    }
  }

  async function handleDeleteUser(userId: string) {
    if (!confirm("Deactivate this user?")) return;
    setDeleteError(null);
    try {
      await deleteUser(userId);
      await fetchUsers();
    } catch (err) {
      setDeleteError(
        (err as { message?: string }).message ?? "Failed to deactivate user.",
      );
    }
  }

  async function handleReactivateUser(userId: string) {
    setDeleteError(null);
    try {
      await reactivateUser(userId);
      await fetchUsers();
    } catch (err) {
      setDeleteError(
        (err as { message?: string }).message ?? "Failed to reactivate user.",
      );
    }
  }

  async function handlePurgeUser(userId: string) {
    if (!confirm("Permanently delete this user? This cannot be undone."))
      return;
    setDeleteError(null);
    try {
      await purgeUser(userId);
      await fetchUsers();
    } catch (err) {
      setDeleteError(
        (err as { message?: string }).message ?? "Failed to delete user.",
      );
    }
  }

  return (
    <div className="space-y-4">
      {/* Header — full width above both panes */}
      <div>
        <EyebrowLabel className="mb-1">User Management</EyebrowLabel>
        <h1 className="text-lg font-semibold text-ink-black dark:text-white">
          Users
        </h1>
        <p className="text-[13px] text-slate-gray dark:text-gray-400 mt-0.5">
          Manage users and password reset requests.
        </p>
      </div>

      {/* Pill segment tabs — full width above both panes */}
      <div className="inline-flex p-1 gap-1 bg-ghost-cream dark:bg-white/5 rounded-pill">
        <button
          type="button"
          onClick={() => setTab("users")}
          className={[
            "px-4 py-1.5 text-[13px] font-medium rounded-pill transition-colors",
            tab === "users"
              ? "bg-ink-black text-canvas-cream"
              : "text-slate-gray dark:text-gray-400 hover:text-ink-black dark:hover:text-gray-200",
          ].join(" ")}
        >
          Users
        </button>
        <button
          type="button"
          onClick={() => setTab("reset_requests")}
          className={[
            "px-4 py-1.5 text-[13px] font-medium rounded-pill transition-colors",
            "flex items-center gap-1.5",
            tab === "reset_requests"
              ? "bg-ink-black text-canvas-cream"
              : "text-slate-gray dark:text-gray-400 hover:text-ink-black dark:hover:text-gray-200",
          ].join(" ")}
        >
          Reset Requests
          {resets.length > 0 && (
            <span className="px-1.5 py-0.5 rounded-pill bg-red-500 text-white text-[10px] font-bold">
              {resets.length}
            </span>
          )}
        </button>
      </div>

      {/* Two-pane grid — starts at same row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
        <div className="space-y-3">
          {/* Error banner — shown for both tabs */}
          {deleteError && (
            <div
              role="alert"
              className="px-3 py-2 rounded-hero bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
            >
              {deleteError}
            </div>
          )}

          {/* Users Tab */}
          {tab === "users" && (
            <div>
              <div className="flex justify-end mb-3">
                <button
                  type="button"
                  onClick={() => setShowModal(true)}
                  className="px-3 py-1.5 text-[13px] rounded-btn bg-ink-black text-canvas-cream font-medium hover:opacity-90"
                >
                  + Add User
                </button>
              </div>

              {loading ? (
                <div className="py-12 text-center text-[13px] text-slate-gray">
                  Loading…
                </div>
              ) : (
                <div className="rounded-hero border border-ghost-cream dark:border-white/5 overflow-hidden shadow-elev-1">
                  <table className="w-full text-[13px]">
                    <thead>
                      <tr className="bg-canvas-cream dark:bg-white/[0.02] border-b border-ghost-cream dark:border-white/5">
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Name
                        </th>
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Email
                        </th>
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Role
                        </th>
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Status
                        </th>
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Accounts
                        </th>
                        <th className="px-4 py-2.5" />
                      </tr>
                    </thead>
                    <tbody className="bg-lifted-cream dark:bg-[#1c1c1b]">
                      {users.map((u) => (
                        <tr
                          key={u.sk}
                          className="border-b border-ghost-cream dark:border-white/5 last:border-0 hover:bg-canvas-cream dark:hover:bg-white/[0.02]"
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <InitialsAvatar name={u.full_name} />
                              <span className="text-ink-black dark:text-white font-medium">
                                {u.full_name}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-slate-gray dark:text-gray-400">
                            {u.email}
                          </td>
                          <td className="px-4 py-3">
                            <RoleBadge role={u.role} />
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`text-[11px] font-medium ${
                                u.is_active
                                  ? "text-green-600 dark:text-green-400"
                                  : "text-slate-gray"
                              }`}
                            >
                              {u.is_active ? "Active" : "Inactive"}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-[12px] text-slate-gray dark:text-gray-400">
                            {accountAccessLabel(u)}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex gap-1.5 justify-end">
                              {u.role !== "admin" && (
                                <button
                                  type="button"
                                  onClick={() => setAssignAccountsUser(u)}
                                  className="px-2.5 py-1 text-[11px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
                                >
                                  Assign
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={() => setPasswordUser(u)}
                                className="px-2.5 py-1 text-[11px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
                              >
                                Set Password
                              </button>
                              <button
                                type="button"
                                onClick={() => setHistoryUser(u)}
                                className="px-2.5 py-1 text-[11px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
                              >
                                History
                              </button>
                              {u.is_active &&
                                (() => {
                                  const activeAdmins = users.filter(
                                    (x) => x.role === "admin" && x.is_active,
                                  );
                                  const isLastAdmin =
                                    u.role === "admin" &&
                                    activeAdmins.length <= 1;
                                  return (
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleDeleteUser(u.sk)
                                      }
                                      disabled={isLastAdmin}
                                      title={
                                        isLastAdmin
                                          ? "Cannot deactivate the last admin"
                                          : undefined
                                      }
                                      className="px-2.5 py-1 text-[11px] rounded-btn border border-red-200 dark:border-red-500/20 text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                      Deactivate
                                    </button>
                                  );
                                })()}
                              {!u.is_active && (
                                <>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      void handleReactivateUser(u.sk)
                                    }
                                    className="px-2.5 py-1 text-[11px] rounded-btn border border-green-200 dark:border-green-500/20 text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-500/10"
                                  >
                                    Reactivate
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => void handlePurgeUser(u.sk)}
                                    className="px-2.5 py-1 text-[11px] rounded-btn border border-red-200 dark:border-red-500/20 text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10"
                                  >
                                    Delete
                                  </button>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                      {users.length === 0 && (
                        <tr>
                          <td
                            colSpan={6}
                            className="px-4 py-8 text-center text-slate-gray"
                          >
                            No users found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {historyUser && (
            <LoginHistoryModal
              user={historyUser}
              onClose={() => setHistoryUser(null)}
            />
          )}

          {passwordUser && (
            <SetPasswordModal
              user={passwordUser}
              onClose={() => setPasswordUser(null)}
            />
          )}

          {assignAccountsUser && (
            <AssignAccountsModal
              user={assignAccountsUser}
              accounts={availableAccounts}
              onClose={() => setAssignAccountsUser(null)}
              onSaved={() => void fetchUsers()}
            />
          )}

          {/* Reset Requests Tab */}
          {tab === "reset_requests" && (
            <div>
              {loading ? (
                <div className="py-12 text-center text-[13px] text-slate-gray">
                  Loading…
                </div>
              ) : resets.length === 0 ? (
                <div className="py-12 text-center text-[13px] text-slate-gray">
                  No pending reset requests.
                </div>
              ) : (
                <div className="rounded-hero border border-ghost-cream dark:border-white/5 overflow-hidden shadow-elev-1">
                  <table className="w-full text-[13px]">
                    <thead>
                      <tr className="bg-canvas-cream dark:bg-white/[0.02] border-b border-ghost-cream dark:border-white/5">
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Name
                        </th>
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Email
                        </th>
                        <th className="text-left px-4 py-2.5 font-medium text-slate-gray dark:text-gray-400">
                          Role
                        </th>
                        <th className="px-4 py-2.5" />
                      </tr>
                    </thead>
                    <tbody className="bg-lifted-cream dark:bg-[#1c1c1b]">
                      {resets.map((u) => (
                        <tr
                          key={u.sk}
                          className="border-b border-ghost-cream dark:border-white/5 last:border-0"
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <InitialsAvatar name={u.full_name} />
                              <span className="text-ink-black dark:text-white font-medium">
                                {u.full_name}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-slate-gray dark:text-gray-400">
                            {u.email}
                          </td>
                          <td className="px-4 py-3">
                            <RoleBadge role={u.role} />
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              onClick={() => void handleApproveReset(u.sk)}
                              className="px-3 py-1 text-[12px] rounded-btn bg-ink-black text-canvas-cream font-medium hover:opacity-90"
                            >
                              Approve
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {showModal && (
            <AddUserModal
              onClose={() => setShowModal(false)}
              onCreated={() => void fetchUsers()}
            />
          )}
        </div>

        {/* Right pane — role permissions matrix */}
        <div className="bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream dark:border-white/5 rounded-hero p-4 shadow-elev-1 sticky top-4">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600 mb-1">
            Reference
          </p>
          <h3 className="text-sm font-bold text-ink-black dark:text-white mb-4">
            Role Permissions
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-[11px] table-fixed">
              <colgroup>
                <col className="w-[45%]" />
                <col className="w-[18%]" />
                <col className="w-[18%]" />
                <col className="w-[19%]" />
              </colgroup>
              <thead>
                <tr>
                  <th className="text-left pb-3 text-slate-gray dark:text-gray-500 font-medium" />
                  {(["Viewer", "Operator", "Admin"] as const).map((r) => (
                    <th
                      key={r}
                      className="pb-3 text-center font-semibold text-ink-black dark:text-gray-300"
                    >
                      {r}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-ghost-cream dark:divide-white/5">
                {[
                  { label: "View dashboard", v: true, o: true, a: true },
                  { label: "View inventory", v: true, o: true, a: true },
                  { label: "View violations", v: true, o: true, a: true },
                  { label: "Trigger scans", v: false, o: true, a: true },
                  { label: "Approve resets", v: false, o: true, a: true },
                  { label: "Jira ticket creation", v: false, o: true, a: true },
                  { label: "Manage users", v: false, o: false, a: true },
                  { label: "Add accounts", v: false, o: false, a: true },
                  { label: "Deactivate users", v: false, o: false, a: true },
                ].map(({ label, v, o, a }) => (
                  <tr
                    key={label}
                    className="hover:bg-ghost-cream/50 dark:hover:bg-white/[0.02]"
                  >
                    <td className="py-1.5 text-slate-gray dark:text-gray-400">
                      {label}
                    </td>
                    {[v, o, a].map((allowed, i) => (
                      <td key={i} className="py-1.5 text-center">
                        {allowed ? (
                          <span className="text-green-600 dark:text-green-400 font-bold">
                            ✓
                          </span>
                        ) : (
                          <span className="text-dust-taupe dark:text-gray-600">
                            —
                          </span>
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
