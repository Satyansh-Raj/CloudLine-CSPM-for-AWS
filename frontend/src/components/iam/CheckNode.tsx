import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { CheckNode } from "@/types/iamGraph";
import { SeverityBadge } from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";

const STATUS_BG: Record<string, string> = {
  alarm: "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800/40",
  ok: "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800/40",
  error:
    "bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800/40",
  skip: "bg-lifted-cream dark:bg-[#1c1c1b] border-ghost-cream dark:border-white/10",
};

export default memo(function CheckNodeComponent({
  data,
}: NodeProps<CheckNode>) {
  const { checkId, violation } = data;
  const { status, severity, risk_score } = violation;

  const bgCls =
    STATUS_BG[status] ??
    "bg-lifted-cream dark:bg-[#1c1c1b] border-ghost-cream dark:border-white/10";

  return (
    <div
      className={[
        "w-44 rounded-xl shadow-elev-1 border select-none cursor-pointer",
        "transition-shadow hover:shadow-elev-2",
        bgCls,
      ].join(" ")}
    >
      <div className="px-3 pt-2.5 pb-2">
        {/* Check name */}
        <p className="text-[11px] font-medium leading-tight mb-2 text-ink-black dark:text-gray-100">
          {getCheckName(checkId)}
        </p>

        <div className="flex items-center justify-between gap-2">
          {/* check_id badge */}
          <span
            className={[
              "px-1.5 py-0.5 rounded-pill text-[9px] font-mono",
              "bg-ghost-cream dark:bg-black/30",
              "text-slate-gray dark:text-gray-400",
              "border border-ghost-cream dark:border-white/10",
            ].join(" ")}
          >
            {checkId}
          </span>

          <SeverityBadge severity={severity} />
        </div>

        {/* Risk score pill */}
        {risk_score !== undefined && (
          <div className="mt-1.5">
            <span
              className={[
                "inline-block px-1.5 py-0.5 rounded-pill",
                "text-[9px] font-medium",
                "bg-ghost-cream dark:bg-black/30",
                "text-slate-gray dark:text-gray-400",
                "border border-ghost-cream dark:border-white/10",
              ].join(" ")}
            >
              Risk: {risk_score}
            </span>
          </div>
        )}
      </div>

      <Handle
        type="target"
        position={Position.Left}
        className="!bg-ghost-cream !border-dust-taupe"
      />
    </div>
  );
});
