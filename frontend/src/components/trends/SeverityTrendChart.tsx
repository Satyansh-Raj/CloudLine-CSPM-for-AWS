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

interface Props {
  data: TrendPoint[];
}

export default function SeverityTrendChart({
  data,
}: Props) {
  return (
    <div>
      <div className="mb-1">
        <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
          Violations by Severity
        </h3>
        <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
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
              className="text-gray-100 dark:text-white/5"
              vertical={false}
            />
            <XAxis
              dataKey="date"
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
            <Tooltip
              contentStyle={{
                fontSize: 12,
                borderRadius: 8,
                border: "1px solid #e5e7eb",
              }}
            />
            <Legend
              iconType="circle"
              iconSize={7}
              wrapperStyle={{
                fontSize: "11px",
                paddingTop: "12px",
              }}
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
