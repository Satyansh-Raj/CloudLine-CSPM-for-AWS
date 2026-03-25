import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { GroupNode } from "@/types/iamGraph";

export default memo(function GroupNodeComponent({
  data,
}: NodeProps<GroupNode>) {
  const { label, alarmCount, isCollapsed } = data;

  return (
    <div
      className={[
        "w-40 rounded-lg shadow-md border",
        "bg-white dark:bg-[#111]",
        "border-gray-200 dark:border-white/10",
        "cursor-pointer select-none",
        "hover:shadow-lg transition-shadow",
      ].join(" ")}
    >
      {/* Header */}
      <div className="flex items-center gap-2 px-3 pt-3 pb-2">
        {/* Folder icon */}
        <svg
          className="w-4 h-4 shrink-0 text-amber-500"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d={
              "M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9" +
              "a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"
            }
          />
        </svg>
        <span
          className={[
            "flex-1 text-xs font-semibold truncate",
            "text-gray-700 dark:text-gray-200",
          ].join(" ")}
          title={label}
        >
          {label}
        </span>
        {/* Collapse chevron */}
        <span
          className={[
            "shrink-0 text-gray-400 dark:text-gray-600",
            "transition-transform duration-200",
            isCollapsed ? "rotate-180" : "",
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

      {/* Alarm badge */}
      {alarmCount > 0 && (
        <div className="px-3 pb-2.5">
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
        </div>
      )}
      {alarmCount === 0 && (
        <div className="px-3 pb-2.5">
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
        </div>
      )}

      <Handle
        type="target"
        position={Position.Left}
        className="!bg-indigo-400 !border-indigo-600"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-gray-400 !border-gray-500"
      />
    </div>
  );
});
