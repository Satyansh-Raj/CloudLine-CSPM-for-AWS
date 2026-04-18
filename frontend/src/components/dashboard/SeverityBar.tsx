import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ResponsiveContainer,
} from "recharts";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

interface Props {
  bySeverity?: Record<string, number>;
}

const SEVERITIES = [
  { key: "critical", label: "Critical", color: "#ef4444" },
  { key: "high", label: "High", color: "#f97316" },
  { key: "medium", label: "Medium", color: "#eab308" },
  { key: "low", label: "Low", color: "#22c55e" },
];

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{
    value: number;
    payload: { name: string };
  }>;
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const { value, payload: item } = payload[0];
  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-dust-taupe dark:border-white/10 rounded-hero px-3 py-1.5 shadow-elev-1">
      <span className="text-sm font-bold text-ink-black dark:text-canvas-cream">
        {value} {item.name}
      </span>
    </div>
  );
}

export default function SeverityBar({ bySeverity = {} }: Props) {
  const data = SEVERITIES.map((s) => ({
    name: s.label,
    key: s.key,
    color: s.color,
    count: bySeverity[s.key] ?? 0,
  }));

  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1 h-full flex flex-col">
      <EyebrowLabel className="mb-1">Severity</EyebrowLabel>
      <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream mb-1">
        Violations by Severity
      </h3>
      <p className="text-xs text-slate-gray mb-4">
        Active violations breakdown
      </p>
      <div className="flex-1 min-h-[11rem]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{ top: 4, right: 4, left: -24, bottom: 0 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="currentColor"
              className="text-ghost-cream dark:text-white/5"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              tick={{ fontSize: 11, fill: "currentColor" }}
              className="text-slate-gray"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fontSize: 11, fill: "currentColor" }}
              className="text-slate-gray"
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={false} />
            <Bar dataKey="count" maxBarSize={48} radius={[6, 6, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.key} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
