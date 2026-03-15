/**
 * KPI stat cards — top row of the dashboard.
 * Shows total checks, violations, passed, and score.
 */
import type { ComplianceScore } from "@/types";
import type { RiskSummary } from "@/types";

interface Props {
    compliance: ComplianceScore;
    risk: RiskSummary;
}

interface KpiItem {
    label: string;
    value: string | number;
    sub?: string;
    accent: string;          // Tailwind text colour for the big number
    trend?: "up" | "down" | "neutral";
}

export default function KpiCards({ compliance, risk }: Props) {
    const cards: KpiItem[] = [
        {
            label: "Total Checks",
            value: compliance.total_checks,
            sub: "policies evaluated",
            accent: "text-gray-900 dark:text-white",
        },
        {
            label: "Active Violations",
            value: compliance.failed,
            sub: `${compliance.passed} passed`,
            accent: compliance.failed > 0 ? "text-red-500" : "text-emerald-500",
        },
        {
            label: "Compliance Score",
            value: `${compliance.score_percent}%`,
            sub: `${compliance.errors} errors · ${compliance.skipped} skipped`,
            accent:
                compliance.score_percent >= 80
                    ? "text-emerald-500"
                    : compliance.score_percent >= 60
                        ? "text-amber-500"
                        : "text-red-500",
        },
        {
            label: "Critical Risks",
            value: compliance.by_severity?.critical ?? 0,
            sub: `${risk.total_scored} resources scored`,
            accent: (compliance.by_severity?.critical ?? 0) > 0 ? "text-red-500" : "text-emerald-500",
        },
    ];

    return (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {cards.map((card) => (
                <div
                    key={card.label}
                    className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 flex flex-col justify-between min-h-[6.5rem] shadow-sm hover:shadow-md dark:hover:shadow-black/20 transition-shadow"
                >
                    {/* Top section — label + value */}
                    <div className="flex flex-col gap-1">
                        <span className="text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                            {card.label}
                        </span>
                        <span className={`text-3xl font-bold leading-none tabular-nums ${card.accent}`}>
                            {card.value}
                        </span>
                    </div>
                    {/* Bottom — sub-label always pinned to bottom */}
                    <span className="text-xs text-gray-400 dark:text-gray-600 truncate">
                        {card.sub ?? "\u00A0"}
                    </span>
                </div>
            ))}
        </div>
    );
}
