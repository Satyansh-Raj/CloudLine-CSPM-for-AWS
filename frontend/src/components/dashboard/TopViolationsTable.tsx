import type { RiskSummaryHighest } from "@/types";
import { getCheckName } from "@/constants/checkNames";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

interface Props {
    items: RiskSummaryHighest[];
}

const SEV_PILL: Record<string, string> = {
    critical: "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400",
    high: "bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400",
    medium: "bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400",
    low: "bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400",
};

function shortArn(arn: string) {
    const parts = arn.split(":");
    const last = parts[parts.length - 1];
    const slashParts = last.split("/");
    return slashParts[slashParts.length - 1] || last || arn;
}

export default function TopViolationsTable({ items }: Props) {
    return (
        <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1 h-full flex flex-col">
            <div className="flex items-center justify-between mb-4">
                <div>
                    <EyebrowLabel className="mb-1">Risk</EyebrowLabel>
                    <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream">
                        Highest Risk Resources
                    </h3>
                    <p className="text-xs text-slate-gray mt-0.5">
                        Top {items.length} by risk score
                    </p>
                </div>
            </div>

            {items.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-32 text-slate-gray">
                    <svg className="w-8 h-8 mb-2 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
                            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <p className="text-xs">No high-risk resources</p>
                </div>
            ) : (
                <div className="space-y-2">
                    {items.map((item, i) => (
                        <div
                            key={`${item.resource_arn}-${item.check_id}`}
                            className="flex items-center gap-3 px-3 py-2.5 rounded-btn bg-canvas-cream dark:bg-[#1c1c1b] hover:bg-ghost-cream dark:hover:bg-white/5 transition-colors"
                        >
                            <span className="w-5 h-5 rounded-full bg-ghost-cream dark:bg-white/10 text-[10px] font-bold text-slate-gray dark:text-canvas-cream flex items-center justify-center shrink-0">
                                {i + 1}
                            </span>

                            <div className="min-w-0 flex-1">
                                <p className="text-xs font-semibold text-ink-black dark:text-canvas-cream truncate">
                                    {shortArn(item.resource_arn)}
                                </p>
                                <p className="text-[10px] text-slate-gray mt-0.5 truncate">
                                    {getCheckName(item.check_id)} · {item.domain.replace(/_/g, " ")}
                                </p>
                            </div>

                            <span className={`px-2 py-0.5 rounded-pill text-[10px] font-semibold capitalize shrink-0 ${SEV_PILL[item.severity] ?? SEV_PILL.medium}`}>
                                {item.severity}
                            </span>

                            <span className="text-sm font-bold tabular-nums text-ink-black dark:text-canvas-cream shrink-0 w-8 text-right">
                                {Math.round(item.risk_score)}
                            </span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
