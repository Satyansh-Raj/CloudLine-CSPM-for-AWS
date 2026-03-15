/**
 * Compliance score card — redesigned with multi-ring concentric donut.
 * One ring per status category (passed / violations / errors / skipped).
 */
import MultiRingDonut from "@/components/shared/MultiRingDonut";
import type { ComplianceScore } from "@/types";

interface Props {
  data: ComplianceScore;
}

export default function ComplianceScoreDonut({ data }: Props) {
  const total = data.total_checks || 1; // guard /0

  const rings = [
    {
      label: "Passed",
      value: data.passed ?? 0,
      pct: ((data.passed ?? 0) / total) * 100,
      color: "#22c55e",
    },
    {
      label: "Violations",
      value: data.failed ?? 0,
      pct: ((data.failed ?? 0) / total) * 100,
      color: "#ef4444",
    },
    {
      label: "Errors",
      value: data.errors ?? 0,
      pct: ((data.errors ?? 0) / total) * 100,
      color: "#f97316",
    },
    {
      label: "Skipped",
      value: data.skipped ?? 0,
      pct: ((data.skipped ?? 0) / total) * 100,
      color: "#94a3b8",
    },
  ].filter((r) => r.value > 0 || r.label === "Passed"); // always show passed ring

  const scoreColor =
    data.score_percent >= 80
      ? "#22c55e"
      : data.score_percent >= 60
        ? "#eab308"
        : "#ef4444";

  return (
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
            Compliance Score
          </h3>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
            {data.total_checks} checks evaluated
          </p>
        </div>
        <span
          className="text-xs font-bold px-2.5 py-1 rounded-full"
          style={{
            backgroundColor: scoreColor + "15",
            color: scoreColor,
          }}
        >
          {data.score_percent >= 80 ? "Good" : data.score_percent >= 60 ? "Fair" : "At Risk"}
        </span>
      </div>

      {/* Ring chart */}
      <div className="flex justify-center">
        <MultiRingDonut
          rings={rings}
          center={`${data.score_percent}%`}
          subCenter="score"
          size={170}
          ringWidth={13}
          gap={18}
        />
      </div>
    </div>
  );
}
