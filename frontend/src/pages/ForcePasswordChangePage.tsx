import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { changePassword } from "@/api/auth";
import type { ApiError } from "@/api/client";
import GhostHeadline from "@/components/shared/GhostHeadline";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

export default function ForcePasswordChangePage() {
  const { refreshMe } = useAuth();
  const navigate = useNavigate();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      await changePassword(currentPassword, newPassword);
      await refreshMe();
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError((err as ApiError).message ?? "Failed to change password.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-canvas-cream dark:bg-ink-black px-4">
      <div className="w-full max-w-sm">
        <div className="relative overflow-hidden bg-lifted-cream dark:bg-ink-black rounded-hero border border-ghost-cream dark:border-white/10 shadow-elev-2 p-6">
          <GhostHeadline className="-bottom-4 -right-4">PASS</GhostHeadline>

          <EyebrowLabel className="mb-3">Account Security</EyebrowLabel>
          <h1 className="text-base font-semibold text-ink-black dark:text-canvas-cream mb-1">
            Change Password
          </h1>
          <p className="text-[12px] text-slate-gray mb-5">
            Enter your current password and choose a new one.
          </p>

          {error && (
            <div
              role="alert"
              className="mb-4 px-3 py-2 rounded-btn bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-3">
            <div>
              <label
                htmlFor="current-password"
                className="block text-[12px] font-medium text-slate-gray mb-1"
              >
                Current Password
              </label>
              <input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-3 py-2 text-[13px] rounded-pill border border-dust-taupe dark:border-white/10 bg-canvas-cream dark:bg-[#0e0e0d] text-ink-black dark:text-canvas-cream outline-none focus:ring-2 focus:ring-ink-black/20 focus:border-ink-black dark:focus:border-canvas-cream/50 dark:focus:ring-canvas-cream/20"
              />
            </div>
            <div>
              <label
                htmlFor="new-password"
                className="block text-[12px] font-medium text-slate-gray mb-1"
              >
                New Password
              </label>
              <input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="w-full px-3 py-2 text-[13px] rounded-pill border border-dust-taupe dark:border-white/10 bg-canvas-cream dark:bg-[#0e0e0d] text-ink-black dark:text-canvas-cream outline-none focus:ring-2 focus:ring-ink-black/20 focus:border-ink-black dark:focus:border-canvas-cream/50 dark:focus:ring-canvas-cream/20"
              />
              <p className="text-[11px] text-slate-gray mt-1">
                Min 12 chars · at least 1 digit · at least 1 symbol
              </p>
            </div>
            <div>
              <label
                htmlFor="confirm-password"
                className="block text-[12px] font-medium text-slate-gray mb-1"
              >
                Confirm Password
              </label>
              <input
                id="confirm-password"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                className="w-full px-3 py-2 text-[13px] rounded-pill border border-dust-taupe dark:border-white/10 bg-canvas-cream dark:bg-[#0e0e0d] text-ink-black dark:text-canvas-cream outline-none focus:ring-2 focus:ring-ink-black/20 focus:border-ink-black dark:focus:border-canvas-cream/50 dark:focus:ring-canvas-cream/20"
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2 text-[13px] font-medium rounded-btn bg-ink-black text-canvas-cream hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {submitting ? "Updating…" : "Change Password"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
