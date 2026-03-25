import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useExecutiveSummary } from "@/hooks/useExecutiveSummary";
import { useRegion } from "@/hooks/useRegion";
import { useAccount } from "@/hooks/useAccount";
import type { DomainBreakdown } from "@/types";

/* ---- constants ---- */

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 dark:text-red-400",
  high: "text-orange-500 dark:text-orange-400",
  medium: "text-yellow-500 dark:text-yellow-400",
  low: "text-green-500 dark:text-green-400",
};

const SEV_BG: Record<string, string> = {
  critical: "bg-red-100 dark:bg-red-500/20 " + "text-red-600 dark:text-red-400",
  high:
    "bg-orange-100 dark:bg-orange-500/20 " +
    "text-orange-600 dark:text-orange-400",
  medium:
    "bg-yellow-100 dark:bg-yellow-500/20 " +
    "text-yellow-600 dark:text-yellow-400",
  low:
    "bg-green-100 dark:bg-green-500/20 " + "text-green-600 dark:text-green-400",
};

/* ---- helpers ---- */

function domainLabel(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function scoreColor(pct: number): string {
  if (pct >= 80) return "text-green-500";
  if (pct >= 60) return "text-yellow-500";
  return "text-red-500";
}

function scoreBarColor(pct: number): string {
  if (pct >= 80) return "bg-green-500";
  if (pct >= 60) return "bg-yellow-500";
  return "bg-red-500";
}

/* ---- KPI card ---- */

interface KpiProps {
  label: string;
  value: string | number;
  color: string;
  testId?: string;
}

function KpiCard({ label, value, color, testId }: KpiProps) {
  return (
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
      <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-2">
        {label}
      </p>
      <p
        className={`text-3xl font-bold tabular-nums ${color}`}
        data-testid={testId}
      >
        {value}
      </p>
    </div>
  );
}

/* ---- loading skeleton ---- */

function LoadingSkeleton() {
  return (
    <div className="space-y-5">
      <div className="animate-pulse grid grid-cols-2 lg:grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div
            key={i}
            className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 h-24"
          >
            <div className="h-3 w-20 bg-gray-200 dark:bg-white/10 rounded mb-3" />
            <div className="h-8 w-16 bg-gray-100 dark:bg-white/5 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---- chart tooltip ---- */

interface DomainTooltipProps {
  active?: boolean;
  payload?: Array<{
    name: string;
    value: number;
    color: string;
  }>;
  label?: string;
}

function DomainTooltip({ active, payload, label }: DomainTooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-white/10 rounded-lg px-3 py-2 shadow-xl text-xs">
      <p className="font-semibold text-gray-700 dark:text-gray-200 mb-1">
        {label}
      </p>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: p.color }}
          />
          <span className="text-gray-500 dark:text-gray-400">{p.name}:</span>
          <span className="font-semibold text-gray-800 dark:text-gray-100">
            {p.value}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ---- domain chart data ---- */

interface DomainChartRow {
  domain: string;
  active: number;
  resolved: number;
  score: number;
}

function buildDomainRows(
  byDomain: Record<string, DomainBreakdown>,
): DomainChartRow[] {
  return Object.entries(byDomain).map(([key, val]) => ({
    domain: domainLabel(key),
    active: val.active,
    resolved: val.resolved,
    score: Math.round(val.score_percent),
  }));
}

/* ---- main page ---- */

export default function ExecutiveSummaryPage() {
  const { selectedRegion, regions, setSelectedRegion } = useRegion();
  const { selectedAccount } = useAccount();

  const { data, isLoading, error } = useExecutiveSummary({
    region: selectedRegion || undefined,
    account_id: selectedAccount || undefined,
  });

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
            Executive Summary
          </h2>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
            Security posture overview
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
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-2xl p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load data:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {/* No data */}
      {!isLoading && !error && !data && (
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-10 text-center shadow-sm">
          <p className="text-sm text-gray-400 dark:text-gray-600">
            No data available. Run a scan to get started.
          </p>
        </div>
      )}

      {/* Content */}
      {!isLoading && !error && data && (
        <>
          {/* KPI row */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <KpiCard
              label="Active Violations"
              value={data.total_active}
              color="text-red-500"
            />
            <KpiCard
              label="Resolved Violations"
              value={data.total_resolved}
              color="text-green-500"
            />
            <KpiCard
              label="Resolution Rate"
              value={`${data.resolution_rate}%`}
              color={
                data.resolution_rate >= 70
                  ? "text-green-500"
                  : data.resolution_rate >= 40
                    ? "text-yellow-500"
                    : "text-red-500"
              }
            />
          </div>

          {/* Severity breakdown */}
          <div
            data-testid="severity-breakdown"
            className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm"
          >
            <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 tracking-tight">
              Severity Breakdown
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {(["critical", "high", "medium", "low"] as const).map((sev) => (
                <div key={sev} className="flex flex-col gap-1">
                  <span
                    className={`text-2xl font-bold tabular-nums ${SEV_COLORS[sev]}`}
                    data-testid={`sev-${sev}`}
                  >
                    {data.by_severity[sev] ?? 0}
                  </span>
                  <span
                    className={`inline-flex w-fit items-center text-[11px] font-medium px-2 py-0.5 rounded-full capitalize ${SEV_BG[sev]}`}
                  >
                    {sev}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Domain compliance */}
          {Object.keys(data.by_domain).length > 0 && (
            <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
              <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 tracking-tight">
                Domain Compliance
              </h3>

              {/* Bar chart */}
              <div className="w-full h-56 mb-4">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={buildDomainRows(data.by_domain)}
                    margin={{
                      top: 4,
                      right: 8,
                      left: -16,
                      bottom: 4,
                    }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="rgba(100,100,100,0.1)"
                      vertical={false}
                    />
                    <XAxis dataKey="domain" tick={{ fontSize: 10 }} />
                    <YAxis tick={{ fontSize: 10 }} />
                    <Tooltip content={<DomainTooltip />} />
                    <Bar
                      dataKey="active"
                      name="Active"
                      fill="#ef4444"
                      radius={[4, 4, 0, 0]}
                    />
                    <Bar
                      dataKey="resolved"
                      name="Resolved"
                      fill="#22c55e"
                      radius={[4, 4, 0, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Domain progress rows */}
              <div className="space-y-3">
                {Object.entries(data.by_domain).map(([key, val]) => {
                  const pct = Math.round(val.score_percent);
                  return (
                    <div key={key}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-medium text-gray-700 dark:text-gray-300 capitalize">
                          {domainLabel(key)}
                        </span>
                        <span
                          className={`text-xs font-bold ${scoreColor(pct)}`}
                        >
                          {pct}%
                        </span>
                      </div>
                      <div className="w-full bg-gray-100 dark:bg-white/10 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full transition-all ${scoreBarColor(pct)}`}
                          style={{
                            width: `${Math.min(100, pct)}%`,
                          }}
                        />
                      </div>
                      <p className="text-[11px] text-gray-400 dark:text-gray-600 mt-0.5">
                        {val.active} active · {val.resolved} resolved ·{" "}
                        {val.total_checks} total checks
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* 24h Trend */}
          <div
            data-testid="trend-section"
            className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm"
          >
            <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 tracking-tight">
              Last 24 Hours
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <span
                  className="text-2xl font-bold tabular-nums text-green-500"
                  data-testid="trend-resolved-24h"
                >
                  {data.trend.resolved_last_24h}
                </span>
                <span className="text-xs text-gray-500 dark:text-gray-400">
                  Resolved
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span
                  className="text-2xl font-bold tabular-nums text-red-500"
                  data-testid="trend-new-24h"
                >
                  {data.trend.new_last_24h}
                </span>
                <span className="text-xs text-gray-500 dark:text-gray-400">
                  New Issues
                </span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
