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
      ? SEVERITY_RING[worstSeverity] ?? "border-gray-300"
      : "border-gray-200 dark:border-white/10";

  return (
    <div
      className={[
        "w-40 rounded-lg shadow-md border-2 select-none",
        "bg-white dark:bg-[#111]",
        ringCls,
      ].join(" ")}
    >
      <div className="flex items-center gap-2 px-3 pt-3 pb-1">
        {/* Key icon */}
        <svg
          className="w-4 h-4 shrink-0 text-purple-500"
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
            className={[
              "block text-xs font-semibold truncate",
              "text-gray-700 dark:text-gray-200",
            ].join(" ")}
            title={rolename}
          >
            {rolename}
          </span>
          <span className="block text-[9px] text-purple-500 dark:text-purple-400">
            Role
          </span>
        </div>
        {/* Collapse chevron */}
        <button
          onClick={() => onToggleCollapse(id)}
          className={[
            "shrink-0 text-gray-400 dark:text-gray-600",
            "hover:text-gray-700 dark:hover:text-gray-300",
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
        className={[
          "px-3 pb-1 text-[9px] truncate",
          "text-gray-400 dark:text-gray-600",
        ].join(" ")}
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
              "px-1.5 py-0.5 rounded text-[10px] font-medium",
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
              "px-1.5 py-0.5 rounded text-[10px] font-medium",
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
        position={Position.Top}
        className="!bg-indigo-400 !border-indigo-600"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="!bg-gray-400 !border-gray-500"
      />
    </div>
  );
});
