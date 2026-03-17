import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { AccountNode } from "@/types/iamGraph";

export default memo(function AccountNodeComponent({
  data,
}: NodeProps<AccountNode>) {
  const { isCollapsed } = data;

  return (
    <div
      className={[
        "px-4 py-3 rounded-xl w-44 shadow-lg",
        "bg-indigo-600 text-white border border-indigo-500",
        "cursor-pointer select-none",
        "hover:bg-indigo-500 transition-colors",
      ].join(" ")}
    >
      <div className="flex items-center gap-2 mb-1">
        {/* Cloud icon */}
        <svg
          className="w-5 h-5 shrink-0"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d={
              "M3 15a4 4 0 004 4h9a5 5 0 10" +
              "-.1-9.999 5.002 5.002 0 10" +
              "-9.78 2.096A4.001 4.001 0 003 15z"
            }
          />
        </svg>
        <span className="text-sm font-semibold flex-1">
          AWS Account
        </span>
        {/* Collapse chevron */}
        <span
          className={[
            "shrink-0 text-indigo-200",
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
      <p className="text-xs text-indigo-200">
        {data.count} {data.label}
        {isCollapsed && " — click to expand"}
      </p>
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-indigo-400 !border-indigo-600"
      />
    </div>
  );
});
