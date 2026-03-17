import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { ServiceNodeRF } from "@/types/iamGraph";

const MAX_ACTIONS = 4;
const MAX_RESOURCES = 3;

export default memo(function ServiceNodeComponent({
  data,
}: NodeProps<ServiceNodeRF>) {
  const {
    serviceName,
    actions,
    resourceName,
    resources,
  } = data;
  const isFullAccess =
    actions.length === 1 && actions[0] === "*";
  const visible = actions.slice(0, MAX_ACTIONS);
  const overflow = actions.length - MAX_ACTIONS;

  const resList = (resources ?? []).filter(
    (r) => r !== "*",
  );
  const hasWildcard = (resources ?? []).includes("*");
  const visibleRes = resList.slice(0, MAX_RESOURCES);
  const resOverflow = resList.length - MAX_RESOURCES;

  return (
    <div
      className={[
        "w-48 rounded-lg shadow-sm border select-none",
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
          {resourceName && (
            <span
              className={[
                "text-[8px] truncate",
                "text-gray-400 dark:text-gray-500",
              ].join(" ")}
              title={resourceName}
            >
              ({resourceName})
            </span>
          )}
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

        {/* Resources */}
        {(visibleRes.length > 0 || hasWildcard) && (
          <div className="mt-1.5 pt-1.5 border-t border-gray-100 dark:border-white/5">
            <p className="text-[8px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-600 mb-0.5">
              Resources
            </p>
            {hasWildcard && resList.length === 0 && (
              <span
                className={[
                  "inline-block px-1 py-0.5",
                  "rounded text-[9px] font-bold",
                  "bg-amber-100 text-amber-700",
                  "dark:bg-amber-900/30",
                  "dark:text-amber-400",
                ].join(" ")}
              >
                * All resources
              </span>
            )}
            <div className="flex flex-col gap-0.5">
              {visibleRes.map((r) => (
                <span
                  key={r}
                  className={[
                    "text-[9px] truncate",
                    "text-gray-600 dark:text-gray-400",
                  ].join(" ")}
                  title={r}
                >
                  {r}
                </span>
              ))}
              {resOverflow > 0 && (
                <span
                  className={[
                    "text-[9px]",
                    "text-gray-400 dark:text-gray-600",
                  ].join(" ")}
                >
                  +{resOverflow} more
                </span>
              )}
            </div>
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
