/**
 * Top violations table — shows highest-risk resources.
 * Matches the "Tables" section of the wireframe.
 */
import type { RiskSummaryHighest } from "@/types";
import { getCheckName } from "@/constants/checkNames";

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
    // Return last two segments of ARN for display
    const parts = arn.split(":");
    const last = parts[parts.length - 1];
    const slashParts = last.split("/");
    return slashParts[slashParts.length - 1] || last || arn;
}

export default function TopViolationsTable({ items }: Props) {
    return (
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm h-full flex flex-col">
            <div className="flex items-center justify-between mb-4">
                <div>
                    <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
                        Highest Risk Resources
                    </h3>
                    <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
                        Top {items.length} by risk score
                    </p>
                </div>
            </div>

            {items.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-32 text-gray-400 dark:text-gray-600">
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
                            className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-gray-50 dark:bg-[#1a1a1a] hover:bg-gray-100 dark:hover:bg-[#222] transition-colors"
                        >
                            {/* Rank */}
                            <span className="w-5 h-5 rounded-full bg-gray-200 dark:bg-white/10 text-[10px] font-bold text-gray-600 dark:text-gray-300 flex items-center justify-center shrink-0">
                                {i + 1}
                            </span>

                            {/* Resource & check */}
                            <div className="min-w-0 flex-1">
                                <p className="text-xs font-semibold text-gray-800 dark:text-white truncate">
                                    {shortArn(item.resource_arn)}
                                </p>
                                <p className="text-[10px] text-gray-500 dark:text-gray-400 mt-0.5 truncate">
                                    {getCheckName(item.check_id)} · {item.domain.replace(/_/g, " ")}
                                </p>
                            </div>

                            {/* Severity pill */}
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold capitalize shrink-0 ${SEV_PILL[item.severity] ?? SEV_PILL.medium}`}>
                                {item.severity}
                            </span>

                            {/* Score */}
                            <span className="text-sm font-bold tabular-nums text-gray-800 dark:text-white shrink-0 w-8 text-right">
                                {Math.round(item.risk_score)}
                            </span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
