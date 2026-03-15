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

interface Props {
  data: TrendPoint[];
}

export default function TrendLineChart({ data }: Props) {
  return (
    <div>
      <div className="mb-1">
        <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
          Violations Over Time
        </h3>
        <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
          Daily new violations, resolutions, and cumulative
          active count
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
              stroke="#f97316"
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
