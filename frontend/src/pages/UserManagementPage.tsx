import { useCallback, useEffect, useState } from "react";
import {
  listUsers,
  createUser,
  approveReset,
  listResetRequests,
  getLoginHistory,
  setUserPassword,
} from "@/api/users";
import type { ApiError } from "@/api/client";
import type { CreateUserRequest, LoginEvent } from "@/api/users";
import type { User, UserRole } from "@/types/auth";

type Tab = "users" | "reset_requests";

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
        className="w-[560px] max-h-[80vh] flex flex-col rounded-2xl bg-white dark:bg-neutral-900 border border-gray-200 dark:border-white/10 shadow-2xl"
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 dark:border-white/5">
          <div>
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">
              Login History
            </h2>
            <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
              {user.full_name} · {user.email}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 text-lg leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-2">
          {loading ? (
            <div className="py-10 text-center text-[13px] text-gray-400">
              Loading…
            </div>
          ) : events.length === 0 ? (
            <div className="py-10 text-center text-[13px] text-gray-400">
              No login events recorded.
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="bg-gray-50 dark:bg-white/[0.02]">
                  <th className="text-left px-3 py-2 font-medium text-gray-500 dark:text-gray-400">
                    Time
                  </th>
                  <th className="text-left px-3 py-2 font-medium text-gray-500 dark:text-gray-400">
                    IP
                  </th>
                  <th className="text-left px-3 py-2 font-medium text-gray-500 dark:text-gray-400">
                    Result
                  </th>
                  <th className="text-left px-3 py-2 font-medium text-gray-500 dark:text-gray-400">
                    User Agent
                  </th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => (
                  <tr
                    key={i}
                    className="border-t border-gray-100 dark:border-white/5"
                  >
                    <td className="px-3 py-2 text-gray-700 dark:text-gray-300 whitespace-nowrap">
                      {new Date(ev.ts).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-gray-500 dark:text-gray-400 font-mono">
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
                      className="px-3 py-2 text-gray-400 truncate max-w-[180px]"
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
      "bg-purple-50 text-purple-700 dark:bg-purple-500/10 dark:text-purple-300",
    operator: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300",
    viewer: "bg-gray-100 text-gray-600 dark:bg-white/5 dark:text-gray-400",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-[11px] font-medium capitalize ${colors[role]}`}
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
        className="w-96 rounded-2xl bg-white dark:bg-neutral-900 border border-gray-200 dark:border-white/10 shadow-2xl p-5"
      >
        <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">
          Add User
        </h2>

        {error && (
          <div
            role="alert"
            className="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
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
            className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
          />
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
          />
          <div>
            <input
              type="password"
              placeholder="Initial Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
            />
            <p className="mt-1 text-[11px] text-gray-400 dark:text-gray-500">
              Min 12 chars · at least 1 digit · at least 1 symbol
            </p>
          </div>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30"
          >
            <option value="viewer">Viewer</option>
            <option value="operator">Operator</option>
            <option value="admin">Admin</option>
          </select>
          <div className="flex gap-2 justify-end pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-[13px] rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-3 py-1.5 text-[13px] rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700 disabled:opacity-50"
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
        className="w-96 rounded-2xl bg-white dark:bg-neutral-900 border border-gray-200 dark:border-white/10 shadow-2xl p-5"
      >
        <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-1">
          Set Password
        </h2>
        <p className="text-[12px] text-gray-500 dark:text-gray-400 mb-4">
          {user.full_name} · {user.email}
        </p>

        {error && (
          <div
            role="alert"
            className="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
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
              className="px-4 py-1.5 text-[13px] rounded-lg bg-gray-100 dark:bg-white/10 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-white/15"
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
                className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
              />
              <p className="mt-1 text-[11px] text-gray-400 dark:text-gray-500">
                Min 12 chars · at least 1 digit · at least 1 symbol
              </p>
            </div>
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
            />
            <div className="flex gap-2 justify-end pt-1">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 text-[13px] rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/5"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="px-3 py-1.5 text-[13px] rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700 disabled:opacity-50"
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

export default function UserManagementPage() {
  const [tab, setTab] = useState<Tab>("users");
  const [users, setUsers] = useState<User[]>([]);
  const [resets, setResets] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [historyUser, setHistoryUser] = useState<User | null>(null);
  const [passwordUser, setPasswordUser] = useState<User | null>(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const [us, rs] = await Promise.all([listUsers(), listResetRequests()]);
      setUsers(us);
      setResets(rs);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchUsers();
  }, [fetchUsers]);

  async function handleApproveReset(userId: string) {
    await approveReset(userId);
    await fetchUsers();
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold text-gray-900 dark:text-white">
            User Management
          </h1>
          <p className="text-[13px] text-gray-500 dark:text-gray-400 mt-0.5">
            Manage users and password reset requests.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-gray-100 dark:border-white/5">
        <button
          type="button"
          onClick={() => setTab("users")}
          className={`px-4 py-2 text-[13px] font-medium border-b-2 transition-colors ${
            tab === "users"
              ? "border-blue-500 text-blue-600 dark:text-blue-400"
              : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          }`}
        >
          Users
        </button>
        <button
          type="button"
          onClick={() => setTab("reset_requests")}
          className={`px-4 py-2 text-[13px] font-medium border-b-2 transition-colors ${
            tab === "reset_requests"
              ? "border-blue-500 text-blue-600 dark:text-blue-400"
              : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          }`}
        >
          Reset Requests
          {resets.length > 0 && (
            <span className="ml-1.5 px-1.5 py-0.5 rounded-full bg-red-500 text-white text-[10px] font-bold">
              {resets.length}
            </span>
          )}
        </button>
      </div>

      {/* Users Tab */}
      {tab === "users" && (
        <div>
          <div className="flex justify-end mb-3">
            <button
              type="button"
              onClick={() => setShowModal(true)}
              className="px-3 py-1.5 text-[13px] rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700"
            >
              + Add User
            </button>
          </div>

          {loading ? (
            <div className="py-12 text-center text-[13px] text-gray-400">
              Loading…
            </div>
          ) : (
            <div className="rounded-xl border border-gray-100 dark:border-white/5 overflow-hidden">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="bg-gray-50 dark:bg-white/[0.02] border-b border-gray-100 dark:border-white/5">
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Name
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Email
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Role
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Status
                    </th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr
                      key={u.sk}
                      className="border-b border-gray-100 dark:border-white/5 last:border-0 hover:bg-gray-50/50 dark:hover:bg-white/[0.02]"
                    >
                      <td className="px-4 py-3 text-gray-900 dark:text-white font-medium">
                        {u.full_name}
                      </td>
                      <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
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
                              : "text-gray-400"
                          }`}
                        >
                          {u.is_active ? "Active" : "Inactive"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex gap-1.5 justify-end">
                          <button
                            type="button"
                            onClick={() => setPasswordUser(u)}
                            className="px-2.5 py-1 text-[11px] rounded-lg border border-gray-200 dark:border-white/10 text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-white/5"
                          >
                            Set Password
                          </button>
                          <button
                            type="button"
                            onClick={() => setHistoryUser(u)}
                            className="px-2.5 py-1 text-[11px] rounded-lg border border-gray-200 dark:border-white/10 text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-white/5"
                          >
                            History
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td
                        colSpan={5}
                        className="px-4 py-8 text-center text-gray-400"
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

      {/* Reset Requests Tab */}
      {tab === "reset_requests" && (
        <div>
          {loading ? (
            <div className="py-12 text-center text-[13px] text-gray-400">
              Loading…
            </div>
          ) : resets.length === 0 ? (
            <div className="py-12 text-center text-[13px] text-gray-400">
              No pending reset requests.
            </div>
          ) : (
            <div className="rounded-xl border border-gray-100 dark:border-white/5 overflow-hidden">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="bg-gray-50 dark:bg-white/[0.02] border-b border-gray-100 dark:border-white/5">
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Name
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Email
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                      Role
                    </th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {resets.map((u) => (
                    <tr
                      key={u.sk}
                      className="border-b border-gray-100 dark:border-white/5 last:border-0"
                    >
                      <td className="px-4 py-3 text-gray-900 dark:text-white font-medium">
                        {u.full_name}
                      </td>
                      <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
                        {u.email}
                      </td>
                      <td className="px-4 py-3">
                        <RoleBadge role={u.role} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => void handleApproveReset(u.sk)}
                          className="px-3 py-1 text-[12px] rounded-lg bg-green-600 text-white font-medium hover:bg-green-700"
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
  );
}
