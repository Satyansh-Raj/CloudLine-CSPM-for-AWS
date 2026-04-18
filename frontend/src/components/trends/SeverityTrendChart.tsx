import {
  AreaChart,
  Area,
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
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/10 rounded-hero px-3 py-2 shadow-elev-2 text-xs">
      <p className="font-semibold text-ink-black dark:text-canvas-cream mb-1">
        {label}
      </p>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: p.color }}
          />
          <span className="text-slate-gray">{p.name}:</span>
          <span className="font-semibold text-ink-black dark:text-canvas-cream">
            {p.value}
          </span>
        </div>
      ))}
    </div>
  );
}

interface Props {
  data: TrendPoint[];
}

export default function SeverityTrendChart({ data }: Props) {
  return (
    <div>
      <div className="mb-1">
        <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream">
          Violations by Severity
        </h3>
        <p className="text-xs text-slate-gray mt-0.5">
          Daily new violations broken down by severity
        </p>
      </div>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
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
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke="#dc2626"
              fill="#dc2626"
              fillOpacity={0.6}
              name="Critical"
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke="#f97316"
              fill="#f97316"
              fillOpacity={0.6}
              name="High"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke="#eab308"
              fill="#eab308"
              fillOpacity={0.6}
              name="Medium"
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke="#22c55e"
              fill="#22c55e"
              fillOpacity={0.6}
              name="Low"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
