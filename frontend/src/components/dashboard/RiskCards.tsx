import type { RiskSummary, RiskCategory } from "@/types";

interface Props {
  data: RiskSummary;
}

const CATEGORY_STYLES: Record<
  RiskCategory,
  { bg: string; text: string; border: string }
> = {
  critical: {
    bg: "bg-red-50 dark:bg-red-900/20",
    text: "text-red-700 dark:text-red-400",
    border: "border-red-200 dark:border-red-800",
  },
  high: {
    bg: "bg-orange-50 dark:bg-orange-900/20",
    text: "text-orange-700 dark:text-orange-400",
    border: "border-orange-200 dark:border-orange-800",
  },
  medium: {
    bg: "bg-yellow-50 dark:bg-yellow-900/20",
    text: "text-yellow-700 dark:text-yellow-400",
    border: "border-yellow-200 dark:border-yellow-800",
  },
  low: {
    bg: "bg-green-50 dark:bg-green-900/20",
    text: "text-green-700 dark:text-green-400",
    border: "border-green-200 dark:border-green-800",
  },
};

const CATEGORY_ORDER: RiskCategory[] = [
  "critical",
  "high",
  "medium",
  "low",
];

export default function RiskCards({ data }: Props) {
  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero shadow-elev-1 p-6">
      <h3 className="text-sm font-medium text-slate-gray mb-4">
        Risk Summary
      </h3>

      <div className="grid grid-cols-2 gap-3 mb-4">
        {CATEGORY_ORDER.map((cat) => {
          const style = CATEGORY_STYLES[cat];
          const count = data.by_category[cat] ?? 0;
          return (
            <div
              key={cat}
              className={`${style.bg} ${style.border} border rounded-btn p-3`}
            >
              <p className={`text-2xl font-bold ${style.text}`}>
                {count}
              </p>
              <p className="text-xs text-slate-gray capitalize">
                {cat}
              </p>
            </div>
          );
        })}
      </div>

      <div className="border-t border-ghost-cream dark:border-white/5 pt-3">
        <p className="text-xs font-medium text-slate-gray mb-2">
          Highest Risk Resources
        </p>
        <div className="space-y-2">
          {data.highest_risk.slice(0, 3).map((item, i) => (
            <div
              key={i}
              className="flex items-center justify-between text-xs"
            >
              <span className="text-ink-black dark:text-canvas-cream truncate max-w-[180px]">
                {item.check_id}
              </span>
              <span
                className={`font-medium ${
                  item.risk_score >= 90
                    ? "text-red-600"
                    : item.risk_score >= 70
                      ? "text-orange-600"
                      : "text-yellow-600"
                }`}
              >
                {item.risk_score}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-ghost-cream dark:border-white/5">
        <p className="text-xs text-slate-gray">
          Total scored: {data.total_scored}
        </p>
      </div>
    </div>
  );
}
