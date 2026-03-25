export default function RiskScoreMeter({
  score,
}: {
  score: number;
}) {
  const { label, bar, text, bg } =
    score >= 76
      ? {
          label: "Critical Risk",
          bar: "bg-red-500",
          text: "text-red-700 dark:text-red-400",
          bg: "bg-red-50 dark:bg-red-500/10 border-red-100 dark:border-red-500/15",
        }
      : score >= 51
        ? {
            label: "High Risk",
            bar: "bg-orange-500",
            text: "text-orange-700 dark:text-orange-400",
            bg: "bg-orange-50 dark:bg-orange-500/10 border-orange-100 dark:border-orange-500/15",
          }
        : score >= 26
          ? {
              label: "Medium Risk",
              bar: "bg-yellow-500",
              text: "text-yellow-700 dark:text-yellow-400",
              bg: "bg-yellow-50 dark:bg-yellow-500/10 border-yellow-100 dark:border-yellow-500/15",
            }
          : {
              label: "Low Risk",
              bar: "bg-green-500",
              text: "text-green-700 dark:text-green-400",
              bg: "bg-green-50 dark:bg-green-500/10 border-green-100 dark:border-green-500/15",
            };

  return (
    <div className={`rounded-2xl border px-5 py-4 shadow-sm ${bg}`}>
      <p className="text-xs font-semibold uppercase tracking-widest text-gray-500 dark:text-gray-400 mb-3">
        Risk Score
      </p>
      <div className="flex items-end gap-2 mb-3">
        <span className={`text-4xl font-black leading-none ${text}`}>
          {score}
        </span>
        <span className="text-sm text-gray-400 dark:text-gray-500 mb-0.5">
          / 100
        </span>
      </div>
      <div className="h-1.5 bg-black/10 dark:bg-white/10 rounded-full overflow-hidden mb-1.5">
        <div
          className={`h-full rounded-full ${bar}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <p className={`text-xs font-semibold ${text}`}>{label}</p>
    </div>
  );
}
