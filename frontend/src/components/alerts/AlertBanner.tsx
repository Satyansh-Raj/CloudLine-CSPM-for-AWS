import { useEffect, useRef } from "react";
import { useAlerts } from "@/hooks/useAlerts";
import type { WsAlert } from "@/types";

const AUTO_DISMISS_MS = 5_000;

const borderColors: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-green-500",
};

const bgColors: Record<string, string> = {
  critical:
    "bg-red-50 dark:bg-red-900/20",
  high:
    "bg-orange-50 dark:bg-orange-900/20",
  medium:
    "bg-yellow-50 dark:bg-yellow-900/20",
  low:
    "bg-green-50 dark:bg-green-900/20",
};

function typeLabel(type: string): string {
  return type === "violation_new"
    ? "New Violation"
    : "Resolved";
}

function ToastItem({
  alert,
  onDismiss,
}: {
  alert: WsAlert;
  onDismiss: (id: string) => void;
}) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    timerRef.current = setTimeout(
      () => onDismiss(alert.id),
      AUTO_DISMISS_MS,
    );
    return () => clearTimeout(timerRef.current);
  }, [alert.id, onDismiss]);

  const severity = alert.data.severity;
  const border = borderColors[severity] ?? "border-l-gray-400";
  const bg = bgColors[severity] ?? "bg-gray-50 dark:bg-gray-800";

  return (
    <div
      className={`border-l-4 ${border} ${bg} rounded-r-lg shadow-lg p-3 w-80 animate-slide-in`}
      role="alert"
    >
      <div className="flex justify-between items-start">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {typeLabel(alert.type)}
            </span>
            <span className="text-xs font-medium capitalize text-gray-600 dark:text-gray-300">
              {severity}
            </span>
          </div>
          <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
            {alert.data.check_id}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
            {alert.data.resource_arn}
          </p>
          {alert.data.risk_score > 0 && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              Risk: {alert.data.risk_score}
            </p>
          )}
        </div>
        <button
          onClick={() => onDismiss(alert.id)}
          className="ml-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
          aria-label="Dismiss"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>
    </div>
  );
}

export default function AlertBanner() {
  const { toasts, dismissToast } = useAlerts();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <ToastItem
          key={t.id}
          alert={t}
          onDismiss={dismissToast}
        />
      ))}
    </div>
  );
}
