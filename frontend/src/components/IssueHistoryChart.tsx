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
import type { StatusHistoryEntry } from "@/types/violation";

/* ---- types ---- */

interface IssueHistoryChartProps {
  statusHistory: StatusHistoryEntry[];
}

interface ChartPoint {
  label: string;
  ts: number;
  /** 1 = alarm, 0 = ok */
  state: number;
  /** 1 during alarm periods, 0 otherwise (red fill) */
  alarm: number;
  /** 1 during ok periods, 0 otherwise (green fill) */
  resolved: number;
}

/* ---- helpers ---- */

function fmtDate(iso: string): string {
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

function isAlarm(status: string): boolean {
  return status === "alarm";
}

const RED = "#ef4444";
const GREEN = "#22c55e";

/**
 * Build chart data with two fill series:
 * - alarm: 1 when in alarm state (red fill, full height)
 * - resolved: 1 when in ok state (green fill, full height)
 * - state: 1=alarm, 0=ok (for the step line)
 */
function buildChartData(history: StatusHistoryEntry[]): ChartPoint[] {
  if (history.length === 0) return [];

  const sorted = [...history].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  const points: ChartPoint[] = [];

  // stepAfter handles holding previous values — no
  // synthetic ts-1 points needed.
  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i];
    const ts = new Date(entry.timestamp).getTime();
    const alarmState = isAlarm(entry.status);

    points.push({
      label: fmtDate(entry.timestamp),
      ts,
      state: alarmState ? 1 : 0,
      alarm: alarmState ? 1 : 0,
      resolved: alarmState ? 0 : 1,
    });
  }

  // Extend to "now"
  const last = sorted[sorted.length - 1];
  const nowTs = Date.now();
  const lastTs = new Date(last.timestamp).getTime();
  if (nowTs - lastTs > 60_000) {
    const alarmState = isAlarm(last.status);
    points.push({
      label: fmtDate(new Date().toISOString()),
      ts: nowTs,
      state: alarmState ? 1 : 0,
      alarm: alarmState ? 1 : 0,
      resolved: alarmState ? 0 : 1,
    });
  }

  return points;
}

/* ---- tooltip ---- */

function HistoryTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { value: number; dataKey?: string }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  const stateVal = payload.find((p) => p.dataKey === "state");
  const val = stateVal?.value ?? payload[0].value;
  const status = val === 1 ? "Alarm" : "Resolved";
  return (
    <div className="bg-white dark:bg-[#1a1a1a] border border-gray-200 dark:border-white/10 rounded-lg px-3 py-2 shadow-xl text-xs">
      <p className="text-gray-500 dark:text-gray-400">{label}</p>
      <p
        className={
          val === 1
            ? "text-red-600 dark:text-red-400 font-semibold"
            : "text-green-600 dark:text-green-400 font-semibold"
        }
      >
        {status}
      </p>
    </div>
  );
}

/* ---- component ---- */

export default function IssueHistoryChart({
  statusHistory,
}: IssueHistoryChartProps) {
  const data = buildChartData(statusHistory);

  if (data.length === 0) {
    return (
      <div data-testid="issue-history-chart" className="w-full">
        <h3 className="text-xs font-semibold uppercase tracking-widest text-gray-500 dark:text-gray-400 mb-3">
          Issue History
        </h3>
        <p className="text-xs text-gray-400 dark:text-gray-600">
          No history available
        </p>
      </div>
    );
  }

  return (
    <div data-testid="issue-history-chart" className="w-full">
      <h3 className="text-xs font-semibold uppercase tracking-widest text-gray-500 dark:text-gray-400 mb-3">
        Issue History
      </h3>
      <ResponsiveContainer width="100%" height={200}>
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
            <linearGradient id="redFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={RED} stopOpacity={0.25} />
              <stop offset="100%" stopColor={RED} stopOpacity={0.05} />
            </linearGradient>
            <linearGradient id="greenFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={GREEN} stopOpacity={0.25} />
              <stop offset="100%" stopColor={GREEN} stopOpacity={0.05} />
            </linearGradient>
            <linearGradient id="lineStroke" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={RED} />
              <stop offset="100%" stopColor={GREEN} />
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
            domain={[-0.05, 1.05]}
            ticks={[0, 1]}
            tickFormatter={(v: number) =>
              v === 1 ? "Alarm" : v === 0 ? "OK" : ""
            }
            tick={{
              fontSize: 10,
              fill: "currentColor",
            }}
            tickLine={false}
            width={48}
          />
          <Tooltip content={<HistoryTooltip />} />
          <ReferenceLine
            y={0}
            stroke="rgba(34,197,94,0.2)"
            strokeDasharray="4 4"
          />
          <ReferenceLine
            y={1}
            stroke="rgba(239,68,68,0.2)"
            strokeDasharray="4 4"
          />

          {/* Red fill: full height during alarm */}
          <Area
            type="stepAfter"
            dataKey="alarm"
            stroke="none"
            fill="url(#redFill)"
            strokeWidth={0}
            dot={false}
            activeDot={false}
            isAnimationActive={false}
          />

          {/* Green fill: full height during resolved */}
          <Area
            type="stepAfter"
            dataKey="resolved"
            stroke="none"
            fill="url(#greenFill)"
            strokeWidth={0}
            dot={false}
            activeDot={false}
            isAnimationActive={false}
          />

          {/* Step line on top with colored dots */}
          <Area
            type="stepAfter"
            dataKey="state"
            stroke="url(#lineStroke)"
            fill="none"
            strokeWidth={2}
            dot={({ cx, cy, payload: p }) => {
              const c = (p as ChartPoint).state === 1 ? RED : GREEN;
              return (
                <circle
                  key={`${cx}-${cy}`}
                  cx={cx}
                  cy={cy}
                  r={4}
                  fill={c}
                  stroke="#fff"
                  strokeWidth={2}
                />
              );
            }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
