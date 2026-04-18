import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAlerts } from "@/hooks/useAlerts";
import { useAuth } from "@/hooks/useAuth";
import { DriftAlertFeed } from "@/components/alerts";

function BellIcon() {
  return (
    <svg
      className="w-5 h-5"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
      />
    </svg>
  );
}
function SunIcon() {
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
        d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364-.707-.707M6.343 6.343l-.707-.707m12.728 0-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
      />
    </svg>
  );
}
function MoonIcon() {
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
        d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
      />
    </svg>
  );
}

export default function Header() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [dark, setDark] = useState(
    () => localStorage.getItem("theme") === "dark",
  );
  const [feedOpen, setFeedOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const feedRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const { unreadCount, status } = useAlerts();

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    }
    if (menuOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [menuOpen]);

  useEffect(() => {
    const root = document.documentElement;
    if (dark) {
      root.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      root.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [dark]);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (feedRef.current && !feedRef.current.contains(e.target as Node)) {
        setFeedOpen(false);
      }
    }
    if (feedOpen) document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [feedOpen]);

  return (
    <header className="shrink-0 px-6 pt-6 pb-2 bg-canvas-cream dark:bg-ink-black">
      <div className="flex items-center justify-between px-5 h-12 rounded-pill bg-lifted-cream dark:bg-[#1c1c1b] shadow-elev-1 gap-4">
        {/* Live indicator */}
        <div className="flex items-center gap-1.5">
          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              status === "connected"
                ? "bg-emerald-500"
                : status === "connecting"
                  ? "bg-amber-400 animate-pulse"
                  : "bg-dust-taupe dark:bg-slate-gray"
            }`}
          />
          <span className="text-xs font-medium text-slate-gray">
            {status === "connected"
              ? "Live"
              : status === "connecting"
                ? "Connecting…"
                : "Offline"}
          </span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-1">
          {/* Bell */}
          <div className="relative" ref={feedRef}>
            <button
              onClick={() => setFeedOpen(!feedOpen)}
              className="relative w-9 h-9 flex items-center justify-center rounded-btn text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/10 hover:text-ink-black dark:hover:text-canvas-cream transition-colors"
              aria-label="Notifications"
            >
              <BellIcon />
              {unreadCount > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-signal-orange rounded-full ring-2 ring-lifted-cream dark:ring-[#1c1c1b]" />
              )}
            </button>
            {feedOpen && (
              <div className="absolute right-0 mt-2 w-80 h-96 flex flex-col bg-lifted-cream dark:bg-ink-black border border-dust-taupe dark:border-white/10 rounded-hero shadow-elev-2 overflow-hidden z-50">
                <DriftAlertFeed
                  onNavigate={(path) => {
                    setFeedOpen(false);
                    navigate(path);
                  }}
                />
              </div>
            )}
          </div>

          {/* Dark toggle */}
          <button
            onClick={() => setDark(!dark)}
            className="w-9 h-9 flex items-center justify-center rounded-btn text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/10 hover:text-ink-black dark:hover:text-canvas-cream transition-colors"
            aria-label="Toggle dark mode"
          >
            {dark ? <SunIcon /> : <MoonIcon />}
          </button>

          {/* User menu */}
          {user && (
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                onClick={() => setMenuOpen((o) => !o)}
                aria-label="User menu"
                className="flex items-center gap-2 px-2.5 py-1.5 rounded-btn text-[13px] text-ink-black dark:text-canvas-cream hover:bg-ghost-cream dark:hover:bg-white/10 transition-colors"
              >
                <span className="w-6 h-6 rounded-full bg-ink-black dark:bg-canvas-cream text-canvas-cream dark:text-ink-black flex items-center justify-center text-[11px] font-semibold shrink-0">
                  {user.full_name?.[0]?.toUpperCase() ?? "U"}
                </span>
                <span className="hidden sm:block max-w-[120px] truncate">
                  {user.email}
                </span>
                <span className="hidden sm:inline px-1.5 py-0.5 rounded-btn text-[10px] font-medium capitalize bg-ghost-cream dark:bg-white/10 text-ink-black dark:text-canvas-cream">
                  {user.role}
                </span>
              </button>
              {menuOpen && (
                <div className="absolute right-0 mt-1 w-44 rounded-xl border border-dust-taupe dark:border-white/10 bg-lifted-cream dark:bg-ink-black shadow-elev-1 overflow-hidden z-50">
                  <button
                    type="button"
                    onClick={() => {
                      setMenuOpen(false);
                      navigate("/account/change-password");
                    }}
                    className="w-full text-left px-3 py-2.5 text-[13px] text-ink-black dark:text-canvas-cream hover:bg-ghost-cream dark:hover:bg-white/5"
                  >
                    Change Password
                  </button>
                  <div className="border-t border-ghost-cream dark:border-white/5">
                    <button
                      type="button"
                      onClick={() => {
                        logout();
                        setMenuOpen(false);
                        navigate("/login");
                      }}
                      className="w-full text-left px-3 py-2.5 text-[13px] text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10"
                    >
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
