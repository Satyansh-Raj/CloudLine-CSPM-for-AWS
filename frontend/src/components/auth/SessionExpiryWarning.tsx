/**
 * SessionExpiryWarning
 *
 * Reads the access token expiry (JWT `exp` claim)
 * from localStorage and shows a modal 2 minutes
 * before the session expires. The user can extend
 * the session (calls /auth/refresh) or let it expire
 * and be logged out.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { AUTH_KEY } from "@/context/AuthContext";
import { refreshToken as refreshTokenApi } from "@/api/auth";

/** Warn when this many ms remain before expiry. */
const WARN_BEFORE_MS = 2 * 60 * 1000; // 2 minutes

function decodeJwtExp(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    const json = atob(
      payload.replace(/-/g, "+").replace(/_/g, "/"),
    );
    const { exp } = JSON.parse(json) as { exp?: number };
    return typeof exp === "number" ? exp * 1000 : null;
  } catch {
    return null;
  }
}

function getStoredTokens(): {
  accessToken: string;
  refreshToken: string;
} | null {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as {
      accessToken: string;
      refreshToken: string;
    };
  } catch {
    return null;
  }
}

export default function SessionExpiryWarning() {
  const [visible, setVisible] = useState(false);
  const [extending, setExtending] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const scheduleWarning = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);

    const tokens = getStoredTokens();
    if (!tokens) return;

    const expMs = decodeJwtExp(tokens.accessToken);
    if (!expMs) return;

    const msUntilWarn = expMs - Date.now() - WARN_BEFORE_MS;
    if (msUntilWarn <= 0) {
      // Already inside the warning window.
      setVisible(true);
      return;
    }

    timerRef.current = setTimeout(() => {
      setVisible(true);
    }, msUntilWarn);
  }, []);

  // Schedule on mount; reschedule whenever
  // localStorage changes (new token after refresh).
  useEffect(() => {
    scheduleWarning();

    const onStorage = (e: StorageEvent) => {
      if (e.key === AUTH_KEY) {
        setVisible(false);
        scheduleWarning();
      }
    };
    window.addEventListener("storage", onStorage);

    return () => {
      window.removeEventListener("storage", onStorage);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [scheduleWarning]);

  async function handleExtend() {
    setExtending(true);
    try {
      const tokens = getStoredTokens();
      if (!tokens) return;
      const newPair = await refreshTokenApi(
        tokens.refreshToken,
      );
      localStorage.setItem(
        AUTH_KEY,
        JSON.stringify({
          accessToken: newPair.access_token,
          refreshToken: newPair.refresh_token,
        }),
      );
      setVisible(false);
      scheduleWarning();
    } catch {
      // Refresh failed — broadcast logout.
      window.dispatchEvent(new CustomEvent("auth:logout"));
    } finally {
      setExtending(false);
    }
  }

  function handleDismiss() {
    setVisible(false);
  }

  if (!visible) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Session expiring soon"
      className="fixed inset-0 z-[9999] flex items-end justify-center pb-6 px-4 pointer-events-none"
    >
      <div className="pointer-events-auto w-full max-w-sm bg-white dark:bg-neutral-900 border border-amber-200 dark:border-amber-500/30 rounded-2xl shadow-2xl p-5">
        <div className="flex items-start gap-3">
          <span className="text-amber-500 text-xl leading-none mt-0.5">
            ⚠
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-semibold text-gray-900 dark:text-white">
              Session expiring soon
            </p>
            <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
              Your session will expire in about 2 minutes.
            </p>
            <div className="flex gap-2 mt-3">
              <button
                type="button"
                onClick={() => void handleExtend()}
                disabled={extending}
                className="px-3 py-1.5 text-[12px] font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {extending ? "Extending…" : "Extend Session"}
              </button>
              <button
                type="button"
                onClick={handleDismiss}
                className="px-3 py-1.5 text-[12px] rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/5"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
