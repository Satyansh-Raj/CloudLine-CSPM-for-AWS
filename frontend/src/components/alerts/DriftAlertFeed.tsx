import { useAlerts } from "@/hooks/useAlerts";
import SeverityBadge from "@/components/shared/SeverityBadge";
import { toViolationPath } from "@/utils/violationUrl";
import type { WsAlert } from "@/types";

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function typeIcon(type: string): string {
  return type === "violation_new" ? "!" : "\u2713";
}

function typeBg(type: string): string {
  return type === "violation_new" ? "bg-red-500" : "bg-green-500";
}

function AlertItem({
  alert,
  onClick,
}: {
  alert: WsAlert;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-7 py-2 hover:bg-canvas-cream dark:hover:bg-white/[0.04] transition-colors ${
        !alert.read ? "bg-ghost-cream dark:bg-white/5" : ""
      }`}
    >
      <div className="flex items-start gap-2">
        <span
          className={`mt-0.5 flex-shrink-0 w-5 h-5 rounded-full ${typeBg(alert.type)} text-white text-xs font-bold flex items-center justify-center`}
        >
          {typeIcon(alert.type)}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-ink-black dark:text-canvas-cream">
              {alert.data.check_id}
            </span>
            <SeverityBadge severity={alert.data.severity} />
          </div>
          <p className="text-xs text-slate-gray truncate mt-0.5">
            {alert.data.resource_arn}
          </p>
          <p className="text-xs text-slate-gray/70 mt-0.5">
            {formatTime(alert.receivedAt)}
          </p>
        </div>
      </div>
    </button>
  );
}

interface Props {
  onNavigate?: (path: string) => void;
}

export default function DriftAlertFeed({ onNavigate }: Props) {
  const { alerts, markRead, markAllRead, status } = useAlerts();

  function handleAlertClick(alert: WsAlert) {
    markRead(alert.id);
    onNavigate?.(toViolationPath(alert.data.check_id, alert.data.resource_arn));
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-7 py-2 border-b border-ghost-cream dark:border-white/5">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream">
            Live Alerts
          </h3>
          <span
            className={`w-2 h-2 rounded-full ${
              status === "connected"
                ? "bg-green-500"
                : status === "connecting"
                  ? "bg-yellow-500 animate-pulse"
                  : "bg-slate-gray/50"
            }`}
            title={status}
          />
        </div>
        {alerts.length > 0 && (
          <button
            onClick={markAllRead}
            className="text-xs text-link-blue hover:opacity-80"
          >
            Mark all read
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto divide-y divide-ghost-cream dark:divide-white/5">
        {alerts.length === 0 ? (
          <div className="px-7 py-4 text-center text-sm text-slate-gray">
            No alerts yet
          </div>
        ) : (
          alerts.map((a) => (
            <AlertItem
              key={a.id}
              alert={a}
              onClick={() => handleAlertClick(a)}
            />
          ))
        )}
      </div>
    </div>
  );
}
