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
        "px-4 py-3 rounded-xl w-44 shadow-elev-2",
        "bg-ink-black text-canvas-cream",
        "border border-[#2a2a29]",
        "cursor-pointer select-none",
        "hover:opacity-90 transition-opacity",
      ].join(" ")}
    >
      <div className="flex items-center gap-2 mb-1">
        {/* Cloud icon */}
        <svg
          className="w-5 h-5 shrink-0 text-canvas-cream/70"
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
        <span className="text-sm font-semibold flex-1 text-canvas-cream">
          AWS Account
        </span>
        {/* Collapse chevron */}
        <span
          className={[
            "shrink-0 text-canvas-cream/50",
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
      <p className="text-xs text-canvas-cream/60">
        {data.count} {data.label}
        {isCollapsed && " — click to expand"}
      </p>
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-canvas-cream/40 !border-canvas-cream/20"
      />
    </div>
  );
});
