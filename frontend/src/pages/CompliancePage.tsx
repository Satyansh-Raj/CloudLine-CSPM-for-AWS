import { useState, useCallback } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { useCompliance } from "@/hooks/useCompliance";
import { useComplianceFramework } from "@/hooks/useComplianceFramework";
import { useRegion } from "@/hooks/useRegion";
import { useAccount } from "@/hooks/useAccount";
import { getControlName } from "@/constants/controlNames";
import type {
  FrameworkSummary,
  ControlStatus,
  ControlViolation,
} from "@/types/compliance";

/* ---- constants ---- */

const FRAMEWORK_LABELS: Record<string, string> = {
  cis_aws: "CIS AWS Foundations Benchmark v1.5.0",
  nist_800_53: "NIST 800-53",
  pci_dss: "PCI DSS v4.0",
  hipaa: "HIPAA",
  soc2: "SOC 2",
  owasp: "OWASP Top 10",
};

// Short labels used inside the compact card (avoids overflow on small viewports)
const FRAMEWORK_CARD_LABELS: Record<string, string> = {
  cis_aws: "CIS AWS v1.5",
  nist_800_53: "NIST 800-53",
  pci_dss: "PCI DSS v4.0",
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

  const cardLabel = FRAMEWORK_CARD_LABELS[id] ?? label;

  return (
    <button
      type="button"
      data-testid={`framework-card-${id}`}
      onClick={onClick}
      className={`
        w-full
        flex flex-col items-center justify-center
        gap-2 text-center
        bg-white dark:bg-[#111]
        border rounded-2xl p-3 shadow-sm
        transition-all duration-200
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
      <div className="flex items-center gap-1 min-w-0">
        <span className="text-blue-500 dark:text-blue-400 shrink-0">
          <ShieldIcon />
        </span>
        <span className="text-[13px] font-semibold text-gray-900 dark:text-white tracking-tight leading-tight">
          {cardLabel}
        </span>
      </div>

      {/* Donut chart */}
      <div className="w-24 h-24 sm:w-28 sm:h-28 lg:w-24 lg:h-24 xl:w-28 xl:h-28 shrink-0">
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
      <span className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white leading-none">
        {score_percent.toFixed(1)}%
      </span>
      <div className="flex flex-col gap-0.5 text-xs sm:text-sm">
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

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      className={`w-3.5 h-3.5 transition-transform duration-200 ${open ? "rotate-90" : ""}`}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      viewBox="0 0 24 24"
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
    </svg>
  );
}

function ViolationRows({ violations }: { violations: ControlViolation[] }) {
  return (
    <>
      {violations.map((v, i) => (
        <tr
          key={`viol-${v.resource_arn}-${i}`}
          className="bg-red-50/30 dark:bg-red-500/[0.04] border-b border-gray-100/50 dark:border-white/5 last:border-0"
        >
          <td
            colSpan={2}
            className="py-1.5 pr-4 pl-8 font-mono text-[11px] text-gray-500 dark:text-gray-400 break-all"
          >
            {v.resource_arn}
          </td>
          <td className="py-1.5 pr-4 text-xs capitalize text-gray-500 dark:text-gray-400">
            {v.severity}
          </td>
          <td
            colSpan={2}
            className="py-1.5 pr-4 text-xs text-gray-500 dark:text-gray-400"
          >
            {v.reason}
          </td>
        </tr>
      ))}
    </>
  );
}

function formatControlId(id: string, _framework: string): string {
  return id;
}

function DrillDown({ framework }: DrillDownProps) {
  const { data, isLoading } = useComplianceFramework(framework);
  const label = FRAMEWORK_LABELS[framework] ?? framework;
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

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
                <th className="text-left py-2 pr-4 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider w-[40%]">
                  Name
                </th>
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
              {data.controls.map((ctrl: ControlStatus) => {
                const hasViolations = ctrl.violations.length > 0;
                const isOpen = expanded.has(ctrl.control_id);
                const resolvedName = getControlName(ctrl.control_id);
                const primaryName =
                  resolvedName !== ctrl.control_id ? resolvedName : "—";
                return (
                  <>
                    <tr
                      key={ctrl.control_id}
                      data-testid={`control-row-${ctrl.control_id}`}
                      onClick={
                        hasViolations
                          ? () => toggle(ctrl.control_id)
                          : undefined
                      }
                      className={`
                        border-b border-gray-50 dark:border-white/5
                        ${!isOpen ? "last:border-0" : ""}
                        ${
                          ctrl.status === "non_compliant"
                            ? "bg-red-50/30 dark:bg-red-500/5"
                            : ""
                        }
                        ${hasViolations ? "cursor-pointer hover:bg-gray-50 dark:hover:bg-white/[0.03] transition-colors" : ""}
                      `}
                    >
                      <td className="py-2.5 pr-4 text-xs text-gray-700 dark:text-gray-300 max-w-xs">
                        <span className="inline-flex items-center gap-1.5">
                          {hasViolations && (
                            <span className="shrink-0">
                              <ChevronIcon open={isOpen} />
                            </span>
                          )}
                          <span>{primaryName}</span>
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-gray-500 dark:text-gray-400">
                        {formatControlId(ctrl.control_id, framework)}
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
                        {hasViolations ? ctrl.violations.length : "—"}
                      </td>
                    </tr>
                    {isOpen && hasViolations && (
                      <ViolationRows
                        key={`${ctrl.control_id}-viols`}
                        violations={ctrl.violations}
                      />
                    )}
                  </>
                );
              })}
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
          className="h-48 bg-gray-100 dark:bg-white/5 rounded-2xl border border-gray-100 dark:border-white/5"
        />
      ))}
    </div>
  );
}

/* ---- main page ---- */

export default function CompliancePage() {
  const { selectedAccount } = useAccount();
  const accountId = selectedAccount || undefined;
  const { data, isLoading, error } = useCompliance(accountId);
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
