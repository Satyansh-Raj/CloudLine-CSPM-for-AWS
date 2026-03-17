import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { PolicyNodeRF } from "@/types/iamGraph";

const TYPE_CLS: Record<string, string> = {
  managed:
    "bg-blue-100 text-blue-700" +
    " dark:bg-blue-900/30 dark:text-blue-400",
  inline:
    "bg-amber-100 text-amber-700" +
    " dark:bg-amber-900/30 dark:text-amber-400",
};

export default memo(function PolicyNodeComponent({
  data,
}: NodeProps<PolicyNodeRF>) {
  const {
    policyName,
    policyType,
    groupName,
    resourceName,
  } = data;

  return (
    <div
      className={[
        "w-44 rounded-lg shadow-sm border select-none",
        "bg-white dark:bg-[#111]",
        "border-gray-200 dark:border-white/10",
      ].join(" ")}
    >
      <div className="px-3 py-2.5">
        <div className="flex items-center gap-1.5 mb-1">
          {/* Shield icon */}
          <svg
            className="w-3.5 h-3.5 shrink-0 text-blue-500"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
          <span
            className={[
              "flex-1 text-[11px] font-medium truncate",
              "text-gray-700 dark:text-gray-200",
            ].join(" ")}
            title={policyName}
          >
            {policyName}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className={[
              "px-1.5 py-0.5 rounded text-[9px] font-medium",
              TYPE_CLS[policyType] ?? TYPE_CLS.inline,
            ].join(" ")}
          >
            {policyType}
          </span>
          {groupName && (
            <span
              className={[
                "text-[9px] truncate",
                "text-gray-400 dark:text-gray-600",
              ].join(" ")}
              title={`via group ${groupName}`}
            >
              via {groupName}
            </span>
          )}
        </div>
        {resourceName && (
          <p
            className={[
              "text-[9px] truncate mt-0.5",
              "text-gray-400 dark:text-gray-500",
            ].join(" ")}
            title={resourceName}
          >
            → {resourceName}
          </p>
        )}
      </div>
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-blue-400 !border-blue-500"
      />
    </div>
  );
});
