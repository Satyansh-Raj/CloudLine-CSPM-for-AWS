import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

interface Props {
  byDomain: Record<string, number>;
}

const PALETTE = [
  "#3b82f6",
  "#8b5cf6",
  "#f97316",
  "#22c55e",
  "#ec4899",
  "#14b8a6",
  "#eab308",
  "#ef4444",
];

function formatLabel(domain: string) {
  return domain
    .replace(/_/g, " ")
    .replace(/\b\w/g, (l) => l.toUpperCase())
    .replace(/Domain \d+/i, (m) => m);
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{
    name: string;
    value: number;
    payload: { color: string; displayValue: string };
  }>;
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const { name, payload: itemPayload } = payload[0];
  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-dust-taupe dark:border-white/10 rounded-hero px-4 py-3 shadow-elev-1 text-xs">
      <div className="flex items-center gap-1.5 font-semibold text-ink-black dark:text-canvas-cream">
        <span
          className="w-2 h-2 rounded-full"
          style={{ backgroundColor: itemPayload.color }}
        />
        {name}: {itemPayload.displayValue}
      </div>
    </div>
  );
}

export default function DomainPieChart({ byDomain }: Props) {
  const entries = Object.entries(byDomain)
    .map(([domain, val]) => ({
      domain,
      count:
        typeof val === "number"
          ? val
          : ((val as { alarm?: number }).alarm ?? 0),
    }))
    .filter((e) => e.count > 0)
    .sort((a, b) => b.count - a.count);

  const total = entries.reduce((s, e) => s + e.count, 0) || 1;

  const data = entries.slice(0, 6).map((e, i) => {
    const sharePct = Math.round((e.count / total) * 100);
    return {
      name: formatLabel(e.domain),
      value: e.count,
      displayValue: `${sharePct}%`,
      color: PALETTE[i % PALETTE.length],
    };
  });

  const isEmpty = data.length === 0;
  const displayData = isEmpty
    ? [{ name: "No data", value: 1, displayValue: "0%", color: "#E8E2DA" }]
    : data;

  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1 h-full flex flex-col">
      <EyebrowLabel className="mb-1">Domains</EyebrowLabel>
      <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream mb-1">
        Violations by Domain
      </h3>
      <p className="text-xs text-slate-gray mb-3">
        Distribution of active alarms
      </p>

      {isEmpty ? (
        <div className="flex flex-col items-center justify-center flex-1 text-slate-gray">
          <svg
            className="w-10 h-10 mb-2 opacity-40"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="1.5"
              d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z"
            />
          </svg>
          <p className="text-xs">No domain data</p>
        </div>
      ) : (
        <div className="flex-1 min-h-[14rem] relative">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={displayData}
                cx="50%"
                cy="44%"
                innerRadius={0}
                outerRadius={75}
                dataKey="value"
                strokeWidth={4}
                className="stroke-lifted-cream dark:stroke-ink-black"
              >
                {displayData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} fillOpacity={0.65} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                iconType="circle"
                iconSize={7}
                wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }}
                formatter={(value: string, entry: any) => (
                  <span className="text-slate-gray">
                    {value}{" "}
                    <span className="font-bold text-ink-black dark:text-canvas-cream">
                      {entry.payload?.displayValue}
                    </span>
                  </span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
