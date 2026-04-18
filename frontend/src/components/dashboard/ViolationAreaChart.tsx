import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

interface Props {
  byDomain?: Record<string, any>;
}

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

function buildChartData(byDomain: Record<string, any>) {
  const domains = Object.keys(byDomain);
  if (domains.length === 0) {
    return [{ name: "Now", critical: 0, high: 0, medium: 0, low: 0 }];
  }
  return domains.map((d) => ({
    name: d.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()),
    critical: byDomain[d].critical ?? 0,
    high: byDomain[d].high ?? 0,
    medium: byDomain[d].medium ?? 0,
    low: byDomain[d].low ?? 0,
  }));
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}

function CustomTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-dust-taupe dark:border-white/10 rounded-hero px-4 py-3 shadow-elev-1 text-xs">
      <p className="font-semibold text-ink-black dark:text-canvas-cream mb-2">
        {label}
      </p>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2 mt-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: p.color }}
          />
          <span className="text-slate-gray capitalize">
            {p.name}:
          </span>
          <span className="font-semibold text-ink-black dark:text-canvas-cream">
            {p.value}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function ViolationAreaChart({ byDomain = {} }: Props) {
  const data = buildChartData(byDomain);

  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1">
      <div className="flex items-center justify-between mb-5">
        <div>
          <EyebrowLabel className="mb-1">Violations</EyebrowLabel>
          <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream">
            Violations by Domain & Severity
          </h3>
          <p className="text-xs text-slate-gray mt-0.5">
            Current scan distribution
          </p>
        </div>
      </div>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={data}
            margin={{ top: 4, right: 4, left: -24, bottom: 0 }}
          >
            <defs>
              {(Object.entries(COLORS) as [string, string][]).map(
                ([key, color]) => (
                  <linearGradient
                    key={key}
                    id={`grad-${key}`}
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="5%" stopColor={color} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={color} stopOpacity={0.02} />
                  </linearGradient>
                ),
              )}
            </defs>
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
            <Tooltip content={<CustomTooltip />} />
            <Legend
              iconType="circle"
              iconSize={7}
              wrapperStyle={{ fontSize: "11px", paddingTop: "12px" }}
            />
            {(Object.entries(COLORS) as [string, string][]).map(
              ([key, color]) => (
                <Area
                  key={key}
                  type="monotone"
                  dataKey={key}
                  name={(key.charAt(0).toUpperCase() + key.slice(1)) as never}
                  stroke={color}
                  strokeWidth={2}
                  fill={`url(#grad-${key})`}
                  dot={false}
                  activeDot={{ r: 4 }}
                />
              ),
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
