import { useState } from "react";
import { useTrends, type Period } from "@/hooks";
import {
  PeriodSelector,
  TrendLineChart,
  SeverityTrendChart,
} from "@/components/trends";
import { AccountBadge } from "@/components/shared";
import { useAccount } from "@/hooks/useAccount";

export default function TrendsPage() {
  const [period, setPeriod] = useState<Period>("7d");
  const { selectedAccount } = useAccount();
  const { trends, isLoading, error } = useTrends(
    period,
    selectedAccount || undefined,
  );

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-baseline gap-3">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
            Trends
          </h2>
          <AccountBadge />
        </div>
        <PeriodSelector value={period} onChange={setPeriod} />
      </div>

      {isLoading && (
        <div className="space-y-5 animate-pulse">
          {[1, 2].map((i) => (
            <div
              key={i}
              className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-6 h-80"
            >
              <div className="h-4 w-40 bg-gray-200 dark:bg-white/10 rounded mb-4" />
              <div className="h-64 bg-gray-100 dark:bg-white/5 rounded-xl" />
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-2xl p-5">
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load trends:{" "}
            {(error as { message?: string }).message ?? "Unknown error"}
          </p>
        </div>
      )}

      {!isLoading && !error && (
        <div className="space-y-5">
          <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-6 shadow-sm">
            <TrendLineChart data={trends} />
          </div>
          <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-6 shadow-sm">
            <SeverityTrendChart data={trends} />
          </div>
        </div>
      )}
    </div>
  );
}
