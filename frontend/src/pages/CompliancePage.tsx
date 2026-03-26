import { useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { useCompliance } from "@/hooks/useCompliance";
import { useComplianceFramework } from "@/hooks/useComplianceFramework";
import { useRegion } from "@/hooks/useRegion";
import type { FrameworkSummary, ControlStatus } from "@/types/compliance";

/* ---- constants ---- */

const FRAMEWORK_LABELS: Record<string, string> = {
  cis_aws: "CIS AWS",
  nist_800_53: "NIST 800-53",
  pci_dss: "PCI DSS",
  hipaa: "HIPAA",
  soc2: "SOC 2",
  owasp: "OWASP Top 10",
};

const ALL_FRAMEWORKS = [
  "cis_aws",
  "nist_800_53",
  "pci_dss",
  "hipaa",
  "soc2",
  "owasp",
] as const;

const COLOR_COMPLIANT = "#22c55e";
const COLOR_NON_COMPLIANT = "#ef4444";

/* ---- icons ---- */

function ShieldIcon() {
  return (
    <svg
      className="w-[18px] h-[18px]"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M12 2l7 4v5c0 5-3.5 9.7-7 11-3.5-1.3-7-6-7-11V6l7-4z"
      />
    </svg>
  );
}

/* ---- framework donut card ---- */

interface FrameworkCardProps {
  id: string;
  label: string;
  summary: FrameworkSummary;
  selected: boolean;
  onClick: () => void;
}

function FrameworkCard({
  id,
  label,
  summary,
  selected,
  onClick,
}: FrameworkCardProps) {
  const { score_percent, compliant, non_compliant } = summary;
  const pieData = [
    { name: "compliant", value: compliant },
    { name: "non_compliant", value: non_compliant },
  ];
  // Edge: if both zero, show a grey full ring
  const isZero = compliant === 0 && non_compliant === 0;
  const safePieData = isZero ? [{ name: "empty", value: 1 }] : pieData;

  return (
    <button
      type="button"
      data-testid={`framework-card-${id}`}
      onClick={onClick}
      className={`
        aspect-square w-full
        flex flex-col items-center justify-center
        gap-2 text-center
        bg-white dark:bg-[#111]
        border rounded-2xl p-3 shadow-sm
        transition-all duration-200 overflow-hidden
        hover:border-gray-200
        dark:hover:border-white/10
        ${
          selected
            ? "border-blue-400 dark:border-blue-500 ring-2 ring-blue-500/20"
            : "border-gray-100 dark:border-white/5 hover:shadow-lg"
        }
      `}
    >
      {/* Header */}
      <div className="flex items-center gap-1">
        <span className="text-blue-500 dark:text-blue-400">
          <ShieldIcon />
        </span>
        <span className="text-xs font-semibold text-gray-900 dark:text-white tracking-tight">
          {label}
        </span>
      </div>

      {/* Donut chart */}
      <div className="w-16 h-16 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={safePieData}
              dataKey="value"
              cx="50%"
              cy="50%"
              innerRadius="55%"
              outerRadius="80%"
              strokeWidth={0}
            >
              {isZero ? (
                <Cell fill="#e5e7eb" />
              ) : (
                pieData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={
                      entry.name === "compliant"
                        ? COLOR_COMPLIANT
                        : COLOR_NON_COMPLIANT
                    }
                  />
                ))
              )}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Score + counts */}
      <span className="text-lg font-bold text-gray-900 dark:text-white leading-none">
        {score_percent.toFixed(1)}%
      </span>
      <div className="flex flex-col gap-0.5 text-[10px]">
        <span className="text-green-600 dark:text-green-400">
          {compliant} compliant
        </span>
        <span className="text-red-500 dark:text-red-400">
          {non_compliant} failed
        </span>
      </div>
    </button>
  );
}

/* ---- drill-down section ---- */

interface DrillDownProps {
  framework: string;
}

function DrillDown({ framework }: DrillDownProps) {
  const { data, isLoading } = useComplianceFramework(framework);
  const label = FRAMEWORK_LABELS[framework] ?? framework;

  return (
    <div
      data-testid="drilldown-section"
      className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm"
    >
      <h3 className="text-base font-bold text-gray-900 dark:text-white mb-4 tracking-tight">
        {label} — Controls
      </h3>

      {isLoading && (
        <div className="animate-pulse space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-10 bg-gray-100 dark:bg-white/5 rounded-lg"
            />
          ))}
        </div>
      )}

      {data && data.controls.length === 0 && (
        <p className="text-sm text-gray-400 dark:text-gray-600 text-center py-8">
          No controls found for this framework.
        </p>
      )}

      {data && data.controls.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 dark:border-white/5">
                <th className="text-left py-2 pr-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Control ID
                </th>
                <th className="text-left py-2 pr-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="text-left py-2 pr-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th className="text-left py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Violations
                </th>
              </tr>
            </thead>
            <tbody>
              {data.controls.map((ctrl: ControlStatus) => (
                <tr
                  key={ctrl.control_id}
                  className={`
                    border-b border-gray-50 dark:border-white/5
                    last:border-0
                    ${
                      ctrl.status === "non_compliant"
                        ? "bg-red-50/30 dark:bg-red-500/5"
                        : ""
                    }
                  `}
                >
                  <td className="py-2.5 pr-4 font-mono text-xs text-gray-700 dark:text-gray-300">
                    {ctrl.control_id}
                  </td>
                  <td className="py-2.5 pr-4">
                    <span
                      data-testid={`status-${ctrl.status}-${ctrl.control_id}`}
                      className={`
                        inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full
                        ${
                          ctrl.status === "compliant"
                            ? "bg-green-100 dark:bg-green-500/20 text-green-600 dark:text-green-400"
                            : "bg-red-100 dark:bg-red-500/20 text-red-600 dark:text-red-400"
                        }
                      `}
                    >
                      {ctrl.status === "compliant"
                        ? "Compliant"
                        : "Non-Compliant"}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className="text-xs capitalize text-gray-600 dark:text-gray-400">
                      {ctrl.severity}
                    </span>
                  </td>
                  <td className="py-2.5 text-xs text-gray-500 dark:text-gray-500">
                    {ctrl.violations.length > 0 ? ctrl.violations.length : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ---- loading skeleton ---- */

function LoadingSkeleton() {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 animate-pulse">
      {Array.from({ length: 6 }).map((_, i) => (
        <div
          key={i}
          className="aspect-square bg-gray-100 dark:bg-white/5 rounded-2xl border border-gray-100 dark:border-white/5"
        />
      ))}
    </div>
  );
}

/* ---- main page ---- */

export default function CompliancePage() {
  const { data, isLoading, error } = useCompliance();
  const { selectedRegion, regions, setSelectedRegion } = useRegion();

  const [selectedFramework, setSelectedFramework] = useState<string>("");

  const byFramework = (
    data as { by_framework?: Record<string, FrameworkSummary> }
  )?.by_framework;
  const hasFrameworks = byFramework && Object.keys(byFramework).length > 0;

  function handleCardClick(fw: string) {
    setSelectedFramework((prev) => (prev === fw ? "" : fw));
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
            Compliance
          </h2>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
            Framework posture across your AWS environment
          </p>
        </div>

        {/* Region selector */}
        <label className="flex items-center gap-2">
          <span className="sr-only">Region</span>
          <select
            aria-label="Region"
            value={selectedRegion}
            onChange={(e) => setSelectedRegion(e.target.value)}
            className="text-[13px] rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-black text-gray-700 dark:text-gray-300 px-3 py-1.5 outline-none focus:ring-2 focus:ring-blue-500/30"
          >
            <option value="">All Regions</option>
            {regions.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
      </div>

      {/* Loading */}
      {isLoading && <LoadingSkeleton />}

      {/* Error */}
      {error && (
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-xl p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load compliance data:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !error && !hasFrameworks && (
        <div className="flex flex-col items-center justify-center py-20 gap-3 text-center">
          <span className="text-gray-300 dark:text-gray-700">
            <ShieldIcon />
          </span>
          <p className="text-sm text-gray-400 dark:text-gray-600">
            No compliance data yet.{" "}
            <span className="font-medium">Run a scan first</span> to populate
            framework scores.
          </p>
        </div>
      )}

      {/* Framework cards grid */}
      {!isLoading && !error && hasFrameworks && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          {ALL_FRAMEWORKS.filter((fw) => byFramework[fw]).map((fw) => (
            <FrameworkCard
              key={fw}
              id={fw}
              label={FRAMEWORK_LABELS[fw] ?? fw}
              summary={byFramework[fw]}
              selected={selectedFramework === fw}
              onClick={() => handleCardClick(fw)}
            />
          ))}
        </div>
      )}

      {/* Drill-down */}
      {selectedFramework !== "" && <DrillDown framework={selectedFramework} />}
    </div>
  );
}
