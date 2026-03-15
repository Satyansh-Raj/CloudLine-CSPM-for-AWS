/**
 * Domain pie chart — shows risk distribution by AWS domain.
 * Fills the third column next to the violations table + severity bar.
 */
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

interface Props {
  byDomain: Record<string, number>;
}

const PALETTE = [
  "#3b82f6", // blue
  "#8b5cf6", // violet
  "#f97316", // orange
  "#22c55e", // green
  "#ec4899", // pink
  "#14b8a6", // teal
  "#eab308", // yellow
  "#ef4444", // red
];

function formatLabel(domain: string) {
  return domain
    .replace(/_/g, " ")
    .replace(/\b\w/g, (l) => l.toUpperCase())
    .replace(/Domain \d+/i, (m) => m);
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; payload: { color: string, displayValue: string } }>;
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const { name, payload: itemPayload } = payload[0];
  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-white/10 rounded-lg px-3 py-2 shadow-xl text-xs">
      <div className="flex items-center gap-1.5 font-semibold text-gray-700 dark:text-gray-200">
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: itemPayload.color }} />
        {name}: {itemPayload.displayValue}
      </div>
    </div>
  );
}

export default function DomainPieChart({ byDomain }: Props) {
  const entries = Object.entries(byDomain)
    .map(([domain, val]) => ({
      domain,
      count: typeof val === "number" ? val : (val as { alarm?: number }).alarm ?? 0,
    }))
    .filter((e) => e.count > 0)
    .sort((a, b) => b.count - a.count);

  const total = entries.reduce((s, e) => s + e.count, 0) || 1;

  const data = entries.slice(0, 6).map((e, i) => {
    const sharePct = Math.round((e.count / total) * 100);
    return {
      name: formatLabel(e.domain),
      value: e.count, // render size based on count
      displayValue: `${sharePct}%`,
      color: PALETTE[i % PALETTE.length],
    };
  });

  const isEmpty = data.length === 0;
  const displayData = isEmpty
    ? [{ name: "No data", value: 1, displayValue: "0%", color: "#e5e7eb" }]
    : data;

  // The pie chart is rendered as a solid pie (innerRadius=0) without centre text.

  return (
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm h-full flex flex-col">
      <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100 mb-1">
        Violations by Domain
      </h3>
      <p className="text-xs text-gray-400 dark:text-gray-600 mb-3">
        Distribution of active alarms
      </p>

      {isEmpty ? (
        <div className="flex flex-col items-center justify-center flex-1 text-gray-300 dark:text-gray-700">
          <svg className="w-10 h-10 mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
              d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z"/>
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
                stroke="#fff" // white thick borders look great with translucency on white backgrounds. On dark, use tailwind trick.
                className="stroke-white dark:stroke-[#111]"
              >
                {displayData.map((entry, i) => (
                  <Cell 
                    key={i} 
                    fill={entry.color} 
                    fillOpacity={0.65} // Translucent!
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                iconType="circle"
                iconSize={7}
                wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }}
                formatter={(value: string, entry: any) => (
                  <span className="text-gray-600 dark:text-gray-400">
                    {value} <span className="font-bold text-gray-800 dark:text-gray-200">{entry.payload?.displayValue}</span>
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
