import type { ComplianceScore } from "@/types";
import type { RiskSummary } from "@/types";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

interface Props {
    compliance: ComplianceScore;
    risk: RiskSummary;
}

interface KpiItem {
    label: string;
    value: string | number;
    sub?: string;
    accent: string;
}

export default function KpiCards({ compliance, risk }: Props) {
    const cards: KpiItem[] = [
        {
            label: "Total Checks",
            value: compliance.total_checks,
            sub: "policies evaluated",
            accent: "text-ink-black dark:text-canvas-cream",
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
        <div className="relative">
            {/* Orbital arc decoration — desktop only */}
            <svg
                aria-hidden
                className="hidden lg:block absolute -top-5 left-[10%] w-[80%] h-10 pointer-events-none overflow-visible"
                viewBox="0 0 100 30"
                preserveAspectRatio="none"
            >
                <path
                    d="M 0 28 Q 50 0 100 28"
                    fill="none"
                    stroke="#F37338"
                    strokeWidth="0.8"
                    strokeDasharray="4 3"
                    opacity="0.3"
                />
            </svg>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                {cards.map((card) => (
                    <div
                        key={card.label}
                        className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 flex flex-col justify-between min-h-[6.5rem] shadow-elev-1 hover:shadow-elev-2 transition-shadow"
                    >
                        <div className="flex flex-col gap-1">
                            <EyebrowLabel>{card.label}</EyebrowLabel>
                            <span className={`text-3xl font-bold leading-none tabular-nums mt-1 ${card.accent}`}>
                                {card.value}
                            </span>
                        </div>
                        <span className="text-xs text-slate-gray truncate mt-2">
                            {card.sub ?? "\u00A0"}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
}
