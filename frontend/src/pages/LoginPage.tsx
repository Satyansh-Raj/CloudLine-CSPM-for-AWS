import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { requestPasswordReset } from "@/api/auth";

export default function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from =
    (location.state as { from?: Location })?.from?.pathname ??
    "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [showReset, setShowReset] = useState(false);
  const [resetEmail, setResetEmail] = useState("");
  const [resetSent, setResetSent] = useState(false);
  const [resetSubmitting, setResetSubmitting] = useState(false);

  if (user) {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ email, password });
      navigate(from, { replace: true });
    } catch (err: unknown) {
      const axiosErr = err as {
        response?: { data?: { reset_required?: boolean } };
      };
      if (axiosErr?.response?.data?.reset_required) {
        navigate("/account/change-password", { replace: true });
        return;
      }
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

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-black px-4">
      <div className="w-full max-w-sm">
        {/* Brand */}
        <div className="flex items-center gap-2.5 mb-8 justify-center">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
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
            <p className="text-[10px] text-gray-400 mt-0.5">
              AWS Security
            </p>
          </div>
        </div>

        <div className="bg-white dark:bg-neutral-900 rounded-2xl border border-gray-200 dark:border-white/10 shadow-sm p-6">
          <h1 className="text-base font-semibold text-gray-900 dark:text-white mb-5">
            Sign in
          </h1>

          {error && (
            <div
              role="alert"
              className="mb-4 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[13px] text-red-600 dark:text-red-400"
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
                    className="block text-[12px] font-medium text-gray-600 dark:text-gray-400 mb-1"
                  >
                    Email
                  </label>
                  <input
                    id="login-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
                  />
                </div>
                <div>
                  <label
                    htmlFor="login-password"
                    className="block text-[12px] font-medium text-gray-600 dark:text-gray-400 mb-1"
                  >
                    Password
                  </label>
                  <input
                    id="login-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
                  />
                </div>
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full py-2 text-[13px] font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed mt-1"
                >
                  {submitting ? "Signing in…" : "Sign In"}
                </button>
              </form>

              <div className="mt-4 text-center">
                <button
                  type="button"
                  onClick={() => setShowReset(true)}
                  className="text-[12px] text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Forgot password? Request reset
                </button>
              </div>
            </>
          ) : (
            <div>
              <p className="text-[13px] text-gray-600 dark:text-gray-400 mb-3">
                Enter your email to request a password reset. An
                admin will approve it.
              </p>
              {resetSent ? (
                <p className="text-[13px] text-green-600 dark:text-green-400">
                  Reset request sent. Contact your admin to approve
                  it.
                </p>
              ) : (
                <form
                  onSubmit={handleResetSubmit}
                  className="space-y-3"
                >
                  <input
                    type="email"
                    placeholder="Email address"
                    value={resetEmail}
                    onChange={(e) => setResetEmail(e.target.value)}
                    required
                    className="w-full px-3 py-2 text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-900 dark:text-white outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400"
                  />
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setShowReset(false)}
                      className="flex-1 py-2 text-[13px] rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/5"
                    >
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={resetSubmitting}
                      className="flex-1 py-2 text-[13px] font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      {resetSubmitting ? "Sending…" : "Send Reset"}
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
