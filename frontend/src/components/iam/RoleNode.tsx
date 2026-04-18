import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { RoleNode } from "@/types/iamGraph";

const SEVERITY_RING: Record<string, string> = {
  critical: "border-red-500",
  high: "border-orange-500",
  medium: "border-yellow-400",
  low: "border-green-500",
};

export default memo(function RoleNodeComponent({
  id,
  data,
}: NodeProps<RoleNode>) {
  const {
    username: rolename,
    arn,
    worstSeverity,
    alarmCount,
    isCollapsed,
    onToggleCollapse,
  } = data;

  const ringCls =
    worstSeverity && alarmCount > 0
      ? (SEVERITY_RING[worstSeverity] ?? "border-ghost-cream")
      : "border-ghost-cream dark:border-white/10";

  return (
    <div
      className={[
        "w-40 rounded-xl shadow-elev-1 border-2 select-none",
        "bg-lifted-cream dark:bg-[#1c1c1b]",
        ringCls,
      ].join(" ")}
    >
      <div className="flex items-center gap-2 px-3 pt-3 pb-1">
        {/* Key icon */}
        <svg
          className="w-4 h-4 shrink-0 text-slate-gray"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d={
              "M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743" +
              " 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586" +
              "a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
            }
          />
        </svg>
        <div className="flex-1 min-w-0">
          <span
            className="block text-xs font-semibold truncate text-ink-black dark:text-gray-200"
            title={rolename}
          >
            {rolename}
          </span>
          <span className="block text-[9px] text-slate-gray dark:text-gray-500">
            Role
          </span>
        </div>
        {/* Collapse chevron */}
        <button
          onClick={() => onToggleCollapse(id)}
          className={[
            "shrink-0 text-slate-gray dark:text-gray-600",
            "hover:text-ink-black dark:hover:text-gray-300",
            "transition-transform duration-200",
            isCollapsed ? "rotate-180" : "",
          ].join(" ")}
          title={isCollapsed ? "Expand" : "Collapse"}
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
        </button>
      </div>

      {/* ARN */}
      <p
        className="px-3 pb-1 text-[9px] truncate text-slate-gray dark:text-gray-600"
        title={arn}
      >
        {arn}
      </p>

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
