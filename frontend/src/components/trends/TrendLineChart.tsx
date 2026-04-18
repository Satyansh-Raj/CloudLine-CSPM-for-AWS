import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import type { TrendPoint } from "@/hooks";

interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{
    name: string;
    value: number;
    color: string;
  }>;
  label?: string;
}

function ChartTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/10 rounded-hero px-4 py-3 shadow-elev-2 text-xs">
      <p className="font-semibold text-ink-black dark:text-canvas-cream mb-1">
        {label}
      </p>
      <div className="space-y-1">
        {payload.map((p) => (
          <div key={p.name} className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: p.color }}
            />
            <span className="text-slate-gray">{p.name}:</span>
            <span className="font-semibold text-ink-black dark:text-canvas-cream">
              {p.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface Props {
  data: TrendPoint[];
}

export default function TrendLineChart({ data }: Props) {
  return (
    <div>
      <div className="mb-1">
        <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream">
          Violations Over Time
        </h3>
        <p className="text-xs text-slate-gray mt-0.5">
          Daily new violations, resolutions, and cumulative active count
        </p>
      </div>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={data}
            margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="currentColor"
              className="text-ghost-cream dark:text-white/5"
              vertical={false}
            />
            <XAxis
              dataKey="date"
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
            <Tooltip content={<ChartTooltip />} />
            <Legend
              iconType="circle"
              iconSize={7}
              wrapperStyle={{ fontSize: "11px", paddingTop: "12px" }}
            />
            <Line
              type="monotone"
              dataKey="violations"
              stroke="#dc2626"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
              name="New Violations"
            />
            <Line
              type="monotone"
              dataKey="resolutions"
              stroke="#22c55e"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
              name="Resolutions"
            />
            <Line
              type="monotone"
              dataKey="active"
              stroke="#F37338"
              strokeWidth={2}
              strokeDasharray="5 3"
              dot={false}
              activeDot={{ r: 4 }}
              name="Active (Cumulative)"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
