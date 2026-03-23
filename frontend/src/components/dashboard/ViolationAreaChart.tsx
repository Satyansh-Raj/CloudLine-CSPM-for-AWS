/**
 * Area chart showing violation trend over severity categories.
 * Uses the by_severity data from the compliance score.
 */
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
interface Props {
  byDomain?: Record<string, any>;
}

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

// Build a single multi-series "snapshot" data point for display
// When real time-series data exists this can be replaced with actual trend data
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
    <div className="bg-white dark:bg-[#1a1a1a] border border-gray-200 dark:border-white/10 rounded-xl px-4 py-3 shadow-xl text-xs">
      <p className="font-semibold text-gray-700 dark:text-gray-100 mb-2">
        {label}
      </p>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2 mt-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: p.color }}
          />
          <span className="text-gray-500 dark:text-gray-300 capitalize">
            {p.name}:
          </span>
          <span className="font-semibold text-gray-800 dark:text-white">
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
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
            Violations by Domain & Severity
          </h3>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
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
              className="text-gray-100 dark:text-white/5"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              tick={{ fontSize: 11, fill: "currentColor" }}
              className="text-gray-400 dark:text-gray-600"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fontSize: 11, fill: "currentColor" }}
              className="text-gray-400 dark:text-gray-600"
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
