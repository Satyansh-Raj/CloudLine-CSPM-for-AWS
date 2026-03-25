import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";

/* ---- types ---- */

interface IssueLifecycleChartProps {
  firstDetected?: string;
  resolvedAt?: string;
  previousStatus?: string;
}

/* ---- helpers ---- */

function fmtDate(iso?: string): string {
  if (!iso) return "Unknown";
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function yTickLabel(value: number): string {
  if (value === 1) return "Alarm";
  if (value === -1) return "Resolved";
  return "";
}

/* ---- chart data ---- */

interface DataPoint {
  label: string;
  state: number;
}

function buildData(firstDetected?: string, resolvedAt?: string): DataPoint[] {
  const pts: DataPoint[] = [];
  pts.push({
    label: fmtDate(firstDetected),
    state: 1,
  });
  if (resolvedAt) {
    pts.push({
      label: fmtDate(resolvedAt),
      state: -1,
    });
  }
  return pts;
}

/* ---- gradient def ---- */

const GRADIENT_ID = "lcGradient";

/* ---- component ---- */

export default function IssueLifecycleChart({
  firstDetected,
  resolvedAt,
}: IssueLifecycleChartProps) {
  const data = buildData(firstDetected, resolvedAt);

  return (
    <div data-testid="lifecycle-chart" className="w-full px-4 py-2">
      <ResponsiveContainer width="100%" height={150}>
        <AreaChart
          data={data}
          margin={{
            top: 10,
            right: 16,
            left: 0,
            bottom: 0,
          }}
        >
          <defs>
            <linearGradient id={GRADIENT_ID} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4} />
              <stop offset="100%" stopColor="#22c55e" stopOpacity={0.4} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.1)" />
          <XAxis
            dataKey="label"
            tick={{
              fontSize: 10,
              fill: "currentColor",
            }}
            tickLine={false}
          />
          <YAxis
            domain={[-1.5, 1.5]}
            ticks={[-1, 1]}
            tickFormatter={yTickLabel}
            tick={{
              fontSize: 10,
              fill: "currentColor",
            }}
            tickLine={false}
            width={52}
          />
          <Tooltip
            formatter={(val) => (Number(val) === 1 ? "Alarm" : "Resolved")}
            labelFormatter={(l) => String(l)}
          />
          <ReferenceLine
            y={0}
            stroke="rgba(128,128,128,0.3)"
            strokeDasharray="4 4"
          />
          <Area
            type="stepAfter"
            dataKey="state"
            stroke={data.length > 1 ? "#22c55e" : "#ef4444"}
            fill={`url(#${GRADIENT_ID})`}
            strokeWidth={2}
            dot={{
              r: 4,
              fill: data.length > 1 ? "#22c55e" : "#ef4444",
            }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
