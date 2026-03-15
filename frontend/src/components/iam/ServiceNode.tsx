import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { ServiceNodeRF } from "@/types/iamGraph";

const MAX_ACTIONS = 4;

export default memo(function ServiceNodeComponent({
  data,
}: NodeProps<ServiceNodeRF>) {
  const { serviceName, actions } = data;
  const isFullAccess =
    actions.length === 1 && actions[0] === "*";
  const visible = actions.slice(0, MAX_ACTIONS);
  const overflow = actions.length - MAX_ACTIONS;

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
          {/* Cube icon */}
          <svg
            className="w-3.5 h-3.5 shrink-0 text-teal-500"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
            />
          </svg>
          <span
            className={[
              "text-[11px] font-semibold uppercase",
              "text-gray-700 dark:text-gray-200",
            ].join(" ")}
          >
            {serviceName}
          </span>
        </div>

        {isFullAccess ? (
          <span
            className={[
              "inline-flex items-center gap-1",
              "px-1.5 py-0.5 rounded text-[9px] font-bold",
              "bg-amber-100 text-amber-700",
              "dark:bg-amber-900/30 dark:text-amber-400",
            ].join(" ")}
          >
            * Full Access
          </span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {visible.map((a) => (
              <span
                key={a}
                className={[
                  "px-1 py-0.5 rounded text-[9px]",
                  "bg-gray-100 text-gray-600",
                  "dark:bg-white/5 dark:text-gray-400",
                ].join(" ")}
              >
                {a}
              </span>
            ))}
            {overflow > 0 && (
              <span
                className={[
                  "px-1 py-0.5 rounded text-[9px]",
                  "text-gray-400 dark:text-gray-600",
                ].join(" ")}
              >
                +{overflow} more
              </span>
            )}
          </div>
        )}
      </div>
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-teal-400 !border-teal-500"
      />
    </div>
  );
});
