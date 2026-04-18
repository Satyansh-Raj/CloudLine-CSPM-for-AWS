import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { UserNode } from "@/types/iamGraph";

const SEVERITY_RING: Record<string, string> = {
  critical: "border-red-500",
  high: "border-orange-500",
  medium: "border-yellow-400",
  low: "border-green-500",
};

export default memo(function UserNodeComponent({
  data,
}: NodeProps<UserNode>) {
  const {
    username,
    arn,
    worstSeverity,
    alarmCount,
    isCollapsed,
    mfaEnabled,
    policyCount,
    groupCount,
    violationCount,
  } = data;

  const ringCls =
    worstSeverity && alarmCount > 0
      ? SEVERITY_RING[worstSeverity] ?? "border-ghost-cream"
      : "border-ghost-cream dark:border-white/10";

  return (
    <div
      className={[
        "w-48 rounded-xl shadow-elev-1 border-2",
        "bg-lifted-cream dark:bg-[#1c1c1b]",
        "cursor-pointer select-none",
        "hover:shadow-elev-2 transition-shadow",
        ringCls,
      ].join(" ")}
    >
      <div className="flex items-center gap-2 px-3 pt-3 pb-1">
        {/* Circular avatar with initials */}
        <span
          className={[
            "w-6 h-6 rounded-full shrink-0 flex items-center justify-center",
            "bg-ink-black text-canvas-cream",
            "text-[9px] font-bold select-none",
          ].join(" ")}
          aria-hidden="true"
        >
          {username.slice(0, 2).toUpperCase()}
        </span>
        <span
          className="flex-1 text-xs font-semibold truncate text-ink-black dark:text-gray-200"
          title={username}
        >
          {username}
        </span>
        {/* Collapse chevron */}
        <span
          className={[
            "shrink-0 text-slate-gray dark:text-gray-600",
            "transition-transform duration-200",
            isCollapsed ? "-rotate-90" : "",
          ].join(" ")}
        >
          <svg
            className="w-3.5 h-3.5"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </span>
      </div>

      {/* ARN */}
      <p
        className="px-3 pb-1 text-[9px] truncate text-slate-gray dark:text-gray-600"
        title={arn}
      >
        {arn}
      </p>

      {/* Count badges row */}
      <div className="flex items-center gap-1.5 px-3 pb-1.5">
        {/* MFA badge */}
        {mfaEnabled !== undefined && (
          <span
            className={[
              "inline-flex items-center gap-0.5",
              "px-1 py-0.5 rounded-pill text-[9px] font-medium",
              mfaEnabled
                ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                : "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
            ].join(" ")}
          >
            {mfaEnabled ? "MFA" : "No MFA"}
          </span>
        )}
        {/* Policy count */}
        {(policyCount ?? 0) > 0 && (
          <span
            className={[
              "inline-flex items-center gap-0.5",
              "px-1 py-0.5 rounded-pill text-[9px] font-medium",
              "bg-ghost-cream text-ink-black",
              "dark:bg-white/10 dark:text-gray-300",
            ].join(" ")}
          >
            <svg
              className="w-2.5 h-2.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
            {policyCount}
          </span>
        )}
        {/* Group count */}
        {(groupCount ?? 0) > 0 && (
          <span
            className={[
              "inline-flex items-center gap-0.5",
              "px-1 py-0.5 rounded-pill text-[9px] font-medium",
              "bg-ghost-cream text-ink-black",
              "dark:bg-white/10 dark:text-gray-300",
            ].join(" ")}
          >
            <svg
              className="w-2.5 h-2.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
            {groupCount}
          </span>
        )}
        {/* Violation count */}
        {(violationCount ?? 0) > 0 && (
          <span
            className={[
              "inline-flex items-center gap-0.5",
              "px-1 py-0.5 rounded-pill text-[9px] font-medium",
              "bg-red-50 text-red-600",
              "dark:bg-red-900/20 dark:text-red-400",
            ].join(" ")}
          >
            <svg
              className="w-2.5 h-2.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"
              />
            </svg>
            {violationCount}
          </span>
        )}
      </div>

      {/* Alarm / ok badge */}
      <div className="px-3 pb-2.5">
        {alarmCount > 0 ? (
          <span
            className={[
              "inline-flex items-center gap-1",
              "px-1.5 py-0.5 rounded-pill text-[10px] font-medium",
              "bg-red-100 text-red-700",
              "dark:bg-red-900/30 dark:text-red-400",
            ].join(" ")}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 dark:bg-red-400 inline-block" />
            {alarmCount} alarm{alarmCount !== 1 ? "s" : ""}
          </span>
        ) : (
          <span
            className={[
              "inline-flex items-center gap-1",
              "px-1.5 py-0.5 rounded-pill text-[10px] font-medium",
              "bg-green-100 text-green-700",
              "dark:bg-green-900/30 dark:text-green-400",
            ].join(" ")}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 dark:bg-green-400 inline-block" />
            All clear
          </span>
        )}
      </div>

      <Handle
        type="target"
        position={Position.Left}
        className="!bg-ink-black/40 !border-ink-black/20"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-ghost-cream !border-dust-taupe"
      />
    </div>
  );
});
