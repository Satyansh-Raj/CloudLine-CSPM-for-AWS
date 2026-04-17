import { useState } from "react";
import { useCompliance, useRiskSummary, useMacieFindings } from "@/hooks";
import { useAccount } from "@/hooks/useAccount";
import {
  KpiCards,
  ViolationAreaChart,
  ComplianceScoreDonut,
  SeverityBar,
  TopViolationsTable,
  DomainPieChart,
} from "@/components/dashboard";
import { AccountBadge } from "@/components/shared";
import { triggerScan } from "@/api";

/* ── Skeleton card ──────────────────────────────── */
function SkeletonCard({ className = "" }: { className?: string }) {
  return (
    <div
      className={`bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 animate-pulse ${className}`}
    >
      <div className="h-3 w-28 bg-gray-200 dark:bg-white/10 rounded mb-3" />
      <div className="h-8 w-20 bg-gray-200 dark:bg-white/10 rounded mb-2" />
      <div className="h-2 w-36 bg-gray-100 dark:bg-white/5 rounded" />
    </div>
  );
}

/* ── Error card ─────────────────────────────────── */
function ErrorCard({ message }: { message: string }) {
  return (
    <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-2xl p-6 flex items-center gap-3">
      <svg
        className="w-5 h-5 text-red-500 shrink-0"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
        />
      </svg>
      <div>
        <p className="text-sm font-semibold text-red-700 dark:text-red-400">
          Failed to load dashboard
        </p>
        <p className="text-xs text-red-500 dark:text-red-500/70 mt-0.5">
          {message}
        </p>
      </div>
    </div>
  );
}

/* ── Scan trigger button ────────────────────────── */
function ScanButton() {
  const { selectedAccount } = useAccount();
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function handleScan() {
    setLoading(true);
    try {
      await triggerScan(selectedAccount || undefined);
      setDone(true);
      setTimeout(() => setDone(false), 4000);
      window.location.reload();
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={handleScan}
      disabled={loading}
      className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all shadow-sm ${
        done
          ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20"
          : "bg-blue-600 hover:bg-blue-700 text-white shadow-blue-500/20 hover:shadow-blue-500/30"
      } disabled:opacity-60 disabled:cursor-not-allowed`}
    >
      {loading ? (
        <>
          <svg
            className="w-3.5 h-3.5 animate-spin"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8v8H4z"
            />
          </svg>
          Scanning…
        </>
      ) : done ? (
        <>✓ Scan complete</>
      ) : (
        <>
          <svg
            className="w-3.5 h-3.5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
          Run Scan
        </>
      )}
    </button>
  );
}

/* ── Macie summary card ─────────────────────────── */
import type { MacieFinding } from "@/types/macie";

function MacieSummaryCard({ findings }: { findings: MacieFinding[] }) {
  const highCount = findings.filter((f) => f.severity === "High").length;

  return (
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
      <h2 className="text-xs uppercase tracking-widest text-gray-400 dark:text-gray-500 mb-3">
        Sensitive Findings
      </h2>
      <div className="flex items-center gap-6">
        <div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {findings.length}
          </p>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
            Total
          </p>
        </div>
        <div>
          <p className="text-2xl font-bold text-red-600 dark:text-red-400">
            {highCount}
          </p>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
            High
          </p>
        </div>
      </div>
    </div>
  );
}

/* ── Page ───────────────────────────────────────── */
export default function DashboardPage() {
  const { selectedAccount } = useAccount();
  const accountId = selectedAccount || undefined;
  const compliance = useCompliance(accountId);
  const risk = useRiskSummary(accountId);
  const macie = useMacieFindings(
    accountId ? { account_id: accountId } : undefined,
  );

  const isLoading = compliance.isLoading || risk.isLoading;
  const error = compliance.error || risk.error;

  /* Loading skeleton */
  if (isLoading) {
    return (
      <div className="space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <div className="h-6 w-36 bg-gray-200 dark:bg-white/10 rounded animate-pulse" />
            <div className="h-3 w-52 bg-gray-100 dark:bg-white/5 rounded mt-2 animate-pulse" />
          </div>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <SkeletonCard className="lg:col-span-2 h-64" />
          <SkeletonCard className="h-64" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <SkeletonCard className="h-64" />
          <SkeletonCard className="h-64" />
          <SkeletonCard className="h-64" />
        </div>
      </div>
    );
  }

  /* Error */
  if (error) {
    return (
      <div className="space-y-5">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">
          Dashboard
        </h2>
        <ErrorCard
          message={(error as { message?: string }).message ?? "Unknown error"}
        />
      </div>
    );
  }

  /* Empty state */
  const complianceData = compliance.data;
  const riskData = risk.data;

  if (!complianceData || !riskData) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4 text-center">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 dark:bg-blue-500/10 flex items-center justify-center">
          <svg
            className="w-8 h-8 text-blue-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="1.5"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
        </div>
        <div>
          <h3 className="text-base font-semibold text-gray-800 dark:text-gray-100">
            No scan data yet
          </h3>
          <p className="text-sm text-gray-400 dark:text-gray-600 mt-1 max-w-xs">
            Run your first scan to populate the dashboard with live findings.
          </p>
        </div>
        <ScanButton />
      </div>
    );
  }

  const highestRisk = riskData.highest_risk?.slice(0, 8) ?? [];
  const bySeverity = complianceData.by_severity ?? {};

  // For domain pie: show the distribution of actual violations (alarms)
  const domainData: Record<string, number> = Object.fromEntries(
    Object.entries(complianceData.by_domain ?? {}).map(([d, v]) => [
      d,
      typeof v === "object" ? ((v as { alarm?: number }).alarm ?? 0) : 0,
    ]),
  );

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
            Dashboard
          </h2>
          <div className="mt-1">
            <AccountBadge />
          </div>
        </div>
        <ScanButton />
      </div>

      {/* Row 1 — KPI cards */}
      <KpiCards compliance={complianceData} risk={riskData} />

      {/* Row 2 — Area chart (2/3) + compliance donut (1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 min-w-0 overflow-hidden">
          <ViolationAreaChart byDomain={complianceData.by_domain ?? {}} />
        </div>
        <div className="min-w-0 overflow-hidden">
          <ComplianceScoreDonut data={complianceData} />
        </div>
      </div>

      {/* Row 3 — Violations table | Severity bar | Domain pie (equal thirds) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="min-w-0 overflow-hidden">
          <TopViolationsTable items={highestRisk} />
        </div>
        <div className="min-w-0 overflow-hidden">
          <SeverityBar bySeverity={bySeverity} />
        </div>
        <div className="min-w-0 overflow-hidden">
          <DomainPieChart byDomain={domainData} />
        </div>
      </div>

      {/* Row 4 — Macie sensitive findings */}
      <MacieSummaryCard findings={macie.data ?? []} />
    </div>
  );
}
