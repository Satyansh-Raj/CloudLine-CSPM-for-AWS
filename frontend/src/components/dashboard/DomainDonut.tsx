import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { DomainScore } from "@/types";

interface Props {
  domains: Record<string, DomainScore>;
}

const DOMAIN_COLORS = [
  "#3b82f6",
  "#8b5cf6",
  "#ec4899",
  "#f59e0b",
  "#10b981",
  "#6366f1",
];

export default function DomainDonut({ domains }: Props) {
  const chartData = Object.entries(domains).map(
    ([name, score]) => ({
      name,
      value: score.failed,
      passed: score.passed,
      total: score.total,
      percent: Math.round(score.score_percent),
    }),
  );

  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero shadow-elev-1 p-6">
      <h3 className="text-sm font-medium text-slate-gray mb-4">
        Failures by Domain
      </h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              outerRadius={80}
              dataKey="value"
              strokeWidth={0}
              label={({ name, percent }) =>
                `${name} ${percent}%`
              }
            >
              {chartData.map((_, i) => (
                <Cell
                  key={i}
                  fill={
                    DOMAIN_COLORS[
                      i % DOMAIN_COLORS.length
                    ]
                  }
                />
              ))}
            </Pie>
            <Tooltip
              formatter={(value) => [
                `${value} failures`,
                "Count",
              ]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
