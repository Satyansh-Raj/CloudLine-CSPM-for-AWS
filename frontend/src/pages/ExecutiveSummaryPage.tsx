import { useCompliance, useRiskSummary } from "@/hooks";
import type { RiskCategory } from "@/types";
import { getCheckName } from "@/constants/checkNames";

/* ── helpers ──────────────────────────────────────── */
interface KpiProps { label: string; value: string | number; color: string }

function KpiCard({ label, value, color }: KpiProps) {
  return (
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
      <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-2">{label}</p>
      <p className={`text-3xl font-bold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

const RISK_COLORS: Record<RiskCategory, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-green-500",
};

function overallStatus(criticals: number, scorePercent: number) {
  if (criticals > 0) return { label: "At Risk", color: "text-red-600 dark:text-red-400", bg: "bg-red-50 dark:bg-red-500/5 border-red-200 dark:border-red-500/20" };
  if (scorePercent < 70) return { label: "Needs Attention", color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-50 dark:bg-orange-500/5 border-orange-200 dark:border-orange-500/20" };
  if (scorePercent < 90) return { label: "Fair", color: "text-yellow-600 dark:text-yellow-400", bg: "bg-yellow-50 dark:bg-yellow-500/5 border-yellow-200 dark:border-yellow-500/20" };
  return { label: "Good", color: "text-green-600 dark:text-green-400", bg: "bg-green-50 dark:bg-green-500/5 border-green-200 dark:border-green-500/20" };
}

const SEV_PILL: Record<string, string> = {
  critical: "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400",
  high: "bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400",
  medium: "bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400",
  low: "bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400",
};

/* ── page ─────────────────────────────────────────── */
export default function ExecutiveSummaryPage() {
  const compliance = useCompliance();
  const risk = useRiskSummary();

  const isLoading = compliance.isLoading || risk.isLoading;
  const error = compliance.error || risk.error;

  /* Loading */
  if (isLoading) {
    return (
      <div>
        <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">Executive Summary</h2>
        <div className="animate-pulse grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 h-24">
              <div className="h-3 w-20 bg-gray-200 dark:bg-white/10 rounded mb-3" />
              <div className="h-8 w-16 bg-gray-100 dark:bg-white/5 rounded" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  /* Error */
  if (error) {
    return (
      <div>
        <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">Executive Summary</h2>
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-2xl p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load data: {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      </div>
    );
  }

  const comp = compliance.data;
  const riskData = risk.data;

  if (!comp || !riskData) {
    return (
      <div>
        <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">Executive Summary</h2>
        <p className="text-gray-400">No data available. Run a scan to get started.</p>
      </div>
    );
  }

  const criticals = comp.by_severity?.critical ?? 0;
  const status = overallStatus(criticals, comp.score_percent);

  return (
    <div className="space-y-5">
      <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">Executive Summary</h2>

      {/* Status banner */}
      <div className={`border rounded-2xl p-5 ${status.bg}`}>
        <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 mb-1">Overall Security Posture</p>
        <p className={`text-2xl font-bold ${status.color}`}>{status.label}</p>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="Compliance Score"
          value={`${Math.round(comp.score_percent)}%`}
          color={comp.score_percent >= 80 ? "text-green-500" : comp.score_percent >= 60 ? "text-yellow-500" : "text-red-500"}
        />
        <KpiCard label="Active Violations" value={comp.failed} color="text-red-500" />
        <KpiCard label="Critical Risks" value={criticals} color={criticals > 0 ? "text-red-500" : "text-green-500"} />
        <KpiCard label="Resources Scored" value={riskData.total_scored} color="text-blue-500" />
      </div>

      {/* Compliance by Domain */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-6 shadow-sm">
        <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100 mb-4">Compliance by Domain</h3>
        {Object.keys(comp.by_domain ?? {}).length === 0 ? (
          <p className="text-sm text-gray-400 dark:text-gray-600">No domain data available.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(comp.by_domain).map(([domain, raw]) => {
              // raw is now a full object {score_percent, total, passed, alarm}
              const score = typeof raw === "object" && raw !== null ? raw as { score_percent: number; total: number; passed: number } : { score_percent: typeof raw === "number" ? raw : 0, total: 0, passed: 0 };
              const pct = Math.round(score.score_percent ?? 0);
              const barColor = pct >= 80 ? "bg-green-500" : pct >= 60 ? "bg-yellow-500" : "bg-red-500";
              return (
                <div key={domain} className="border border-gray-100 dark:border-white/8 rounded-xl p-4 bg-gray-50 dark:bg-[#1a1a1a]">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-sm font-semibold text-gray-900 dark:text-gray-100 capitalize">
                      {domain.replace(/_/g, " ")}
                    </p>
                    <span className={`text-sm font-bold ${pct >= 80 ? "text-green-500" : pct >= 60 ? "text-yellow-500" : "text-red-500"}`}>
                      {pct}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-white/15 rounded-full h-1.5">
                    <div className={`${barColor} h-1.5 rounded-full transition-all`} style={{ width: `${Math.min(100, pct)}%` }} />
                  </div>
                  {score.total > 0 && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1.5">
                      {score.passed}/{score.total} passed
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Highest risk resources */}
      <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">Highest Risk Resources</h3>
          <span className="text-xs text-gray-400">{riskData.highest_risk.length} total</span>
        </div>
        {riskData.highest_risk.length === 0 ? (
          <p className="text-sm text-gray-400">No risk data available.</p>
        ) : (
          <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
            <table className="min-w-full">
              <thead className="sticky top-0 bg-white dark:bg-[#111]">
                <tr className="border-b border-gray-100 dark:border-white/5">
                  {["Issue", "Resource", "Severity", "Domain", "Risk Score"].map((h, i) => (
                    <th key={h} className={`pb-3 text-xs font-semibold text-gray-400 uppercase tracking-wider ${i === 4 ? "text-right" : "text-left"} pr-4`}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50 dark:divide-white/5">
                {riskData.highest_risk.map((item, i) => {
                  const cat: RiskCategory =
                    item.risk_score >= 90 ? "critical"
                      : item.risk_score >= 70 ? "high"
                        : item.risk_score >= 40 ? "medium"
                          : "low";
                  return (
                    <tr key={i} className="hover:bg-gray-50 dark:hover:bg-white/[0.06] transition-colors">
                      <td className="py-3 pr-4">
                        <span className="text-xs text-gray-900 dark:text-gray-100 block">{getCheckName(item.check_id)}</span>
                        <span className="text-[10px] font-mono text-gray-400 dark:text-gray-500">{item.check_id}</span>
                      </td>
                      <td className="py-3 pr-4 text-xs font-mono text-gray-600 dark:text-gray-300 max-w-[160px] truncate" title={item.resource_arn}>{item.resource_arn.split(":").pop()}</td>
                      <td className="py-3 pr-4">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold capitalize ${SEV_PILL[item.severity] ?? SEV_PILL.medium}`}>
                          {item.severity}
                        </span>
                      </td>
                      <td className="py-3 pr-4 text-xs capitalize text-gray-500 dark:text-gray-400">{item.domain.replace(/_/g, " ")}</td>
                      <td className={`py-3 text-sm font-bold text-right ${RISK_COLORS[cat]}`}>{Math.round(item.risk_score)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
