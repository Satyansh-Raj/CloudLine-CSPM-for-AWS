import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { requestPasswordReset, resetPassword } from "@/api/auth";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

export default function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from =
    (location.state as { from?: Location })?.from?.pathname ?? "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [showReset, setShowReset] = useState(false);
  const [resetEmail, setResetEmail] = useState("");
  const [resetSent, setResetSent] = useState(false);
  const [resetSubmitting, setResetSubmitting] = useState(false);

  // Set-new-password form (shown after admin approves)
  const [showSetPassword, setShowSetPassword] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [setPasswordError, setSetPasswordError] = useState<string | null>(null);
  const [setPasswordDone, setSetPasswordDone] = useState(false);
  const [setPasswordSubmitting, setSetPasswordSubmitting] = useState(false);

  if (user) {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const me = await login({ email, password });
      if (me.reset_allowed) {
        navigate("/account/change-password", { replace: true });
        return;
      }
      navigate(from, { replace: true });
    } catch {
      setError("Invalid email or password.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleResetSubmit(e: React.FormEvent) {
    e.preventDefault();
    setResetSubmitting(true);
    try {
      await requestPasswordReset(resetEmail);
      setResetSent(true);
    } finally {
      setResetSubmitting(false);
    }
  }

  async function handleSetPassword(e: React.FormEvent) {
    e.preventDefault();
    setSetPasswordError(null);
    if (newPassword !== confirmPassword) {
      setSetPasswordError("Passwords do not match.");
      return;
    }
    setSetPasswordSubmitting(true);
    try {
      await resetPassword(resetEmail, newPassword);
      setSetPasswordDone(true);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setSetPasswordError(msg ?? "Failed to reset password. Check that the reset was approved.");
    } finally {
      setSetPasswordSubmitting(false);
    }
  }

  const inputCls =
    "w-full px-3 py-2 text-[13px] rounded-pill border border-dust-taupe dark:border-white/10 " +
    "bg-canvas-cream dark:bg-[#0e0e0d] text-ink-black dark:text-canvas-cream " +
    "outline-none focus:ring-2 focus:ring-ink-black/20 focus:border-ink-black " +
    "dark:focus:border-canvas-cream/50 dark:focus:ring-canvas-cream/20";

  return (
    <div className="min-h-screen flex items-center justify-center bg-canvas-cream dark:bg-ink-black px-4">
      <div className="w-full max-w-sm">
        {/* Brand */}
        <div className="flex items-center gap-2.5 mb-8 justify-center">
          <div className="w-8 h-8 rounded-full bg-ink-black dark:bg-canvas-cream flex items-center justify-center">
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

        <div className="bg-lifted-cream dark:bg-ink-black rounded-hero border border-ghost-cream dark:border-white/10 shadow-elev-2 p-6">
          <EyebrowLabel className="mb-3">Secure Access</EyebrowLabel>
          <h1 className="text-base font-semibold text-ink-black dark:text-canvas-cream mb-5">
            Sign in
          </h1>

          {error && (
            <div
              role="alert"
              className="mb-4 px-3 py-2 rounded-btn bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
            >
              {error}
            </div>
          )}

          {!showReset ? (
            <>
              <form onSubmit={handleSubmit} className="space-y-3">
                <div>
                  <label
                    htmlFor="login-email"
                    className="block text-[12px] font-medium text-slate-gray mb-1"
                  >
                    Email
                  </label>
                  <input
                    id="login-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className={inputCls}
                  />
                </div>
                <div>
                  <label
                    htmlFor="login-password"
                    className="block text-[12px] font-medium text-slate-gray mb-1"
                  >
                    Password
                  </label>
                  <input
                    id="login-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className={inputCls}
                  />
                </div>
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full py-2 text-[13px] font-medium rounded-btn bg-ink-black text-canvas-cream hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed mt-1"
                >
                  {submitting ? "Signing in…" : "Sign In"}
                </button>
              </form>

              <div className="mt-4 text-center">
                <button
                  type="button"
                  onClick={() => setShowReset(true)}
                  className="text-[12px] text-ink-black dark:text-canvas-cream hover:underline"
                >
                  Forgot password? Request reset
                </button>
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <p className="text-[13px] text-slate-gray">
                Enter your email to request a password reset. An admin will
                approve it.
              </p>

              {/* Stage 1 — Request reset */}
              {!resetSent ? (
                <form onSubmit={handleResetSubmit} className="space-y-3">
                  <input
                    type="email"
                    placeholder="Email address"
                    value={resetEmail}
                    onChange={(e) => setResetEmail(e.target.value)}
                    required
                    className={inputCls}
                  />
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setShowReset(false)}
                      className="flex-1 py-2 text-[13px] rounded-btn text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5"
                    >
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={resetSubmitting}
                      className="flex-1 py-2 text-[13px] font-medium rounded-btn bg-ink-black text-canvas-cream hover:opacity-90 disabled:opacity-40"
                    >
                      {resetSubmitting ? "Sending…" : "Send Reset Request"}
                    </button>
                  </div>
                </form>
              ) : (
                /* Stage 2 — Request sent, waiting for admin / set new password */
                <div className="space-y-4">
                  <div className="px-3 py-2 rounded-btn bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 text-[12px] text-green-700 dark:text-green-400">
                    Reset request sent. Contact your admin to approve it.
                  </div>

                  {/* Set new password — shown after admin approves */}
                  {!showSetPassword ? (
                    <button
                      type="button"
                      onClick={() => setShowSetPassword(true)}
                      className="w-full py-2 text-[13px] rounded-btn border border-ghost-cream dark:border-white/10 text-slate-gray dark:text-gray-400 hover:bg-ghost-cream dark:hover:bg-white/5"
                    >
                      Admin approved it — Set new password
                    </button>
                  ) : setPasswordDone ? (
                    <div className="space-y-3">
                      <div className="px-3 py-2 rounded-btn bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 text-[12px] text-green-700 dark:text-green-400">
                        Password updated successfully.
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setShowReset(false);
                          setResetSent(false);
                          setShowSetPassword(false);
                          setSetPasswordDone(false);
                          setNewPassword("");
                          setConfirmPassword("");
                          setResetEmail("");
                        }}
                        className="w-full py-2 text-[13px] font-medium rounded-btn bg-ink-black text-canvas-cream hover:opacity-90"
                      >
                        Back to Sign In
                      </button>
                    </div>
                  ) : (
                    <form onSubmit={handleSetPassword} className="space-y-3">
                      <p className="text-[12px] font-medium text-slate-gray">
                        Set your new password
                      </p>
                      {setPasswordError && (
                        <div
                          role="alert"
                          className="px-3 py-2 rounded-btn bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[12px] text-red-600 dark:text-red-400"
                        >
                          {setPasswordError}
                        </div>
                      )}
                      <input
                        type="email"
                        placeholder="Your email"
                        value={resetEmail}
                        onChange={(e) => setResetEmail(e.target.value)}
                        required
                        className={inputCls}
                      />
                      <div>
                        <input
                          type="password"
                          placeholder="New password"
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          required
                          className={inputCls}
                        />
                        <p className="mt-1 text-[11px] text-slate-gray">
                          Min 12 chars · at least 1 digit · at least 1 symbol
                        </p>
                      </div>
                      <input
                        type="password"
                        placeholder="Confirm new password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        className={inputCls}
                      />
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setShowSetPassword(false)}
                          className="flex-1 py-2 text-[13px] rounded-btn text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5"
                        >
                          Back
                        </button>
                        <button
                          type="submit"
                          disabled={setPasswordSubmitting}
                          className="flex-1 py-2 text-[13px] font-medium rounded-btn bg-ink-black text-canvas-cream hover:opacity-90 disabled:opacity-40"
                        >
                          {setPasswordSubmitting ? "Saving…" : "Set Password"}
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              )}

              <div className="text-center">
                <button
                  type="button"
                  onClick={() => {
                    setShowReset(false);
                    setResetSent(false);
                    setShowSetPassword(false);
                  }}
                  className="text-[12px] text-slate-gray hover:underline"
                >
                  ← Back to Sign In
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
