import { useMemo } from "react";
import { useDriftAlerts } from "./useDriftAlerts";
import { useCompliance } from "./useCompliance";

export type Period = "7d" | "30d" | "90d";

export interface TrendPoint {
  date: string;
  violations: number;
  resolutions: number;
  active: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

function daysAgo(days: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - days);
  d.setHours(0, 0, 0, 0);
  return d;
}

function formatDate(d: Date): string {
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${m}/${day}`;
}

function localKey(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

const PERIOD_DAYS: Record<Period, number> = {
  "7d": 7,
  "30d": 30,
  "90d": 90,
};

export function useTrends(period: Period, accountId?: string) {
  const days = PERIOD_DAYS[period];
  const {
    data: alertData,
    isLoading: alertsLoading,
    error: alertsError,
  } = useDriftAlerts({ limit: 1000, account_id: accountId || undefined });
  const {
    data: complianceData,
    isLoading: compLoading,
    error: compError,
  } = useCompliance();

  const trends = useMemo(() => {
    if (!alertData?.alerts) return [];

    const cutoff = daysAgo(days);
    const buckets = new Map<string, TrendPoint>();

    // Initialize all date buckets
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const key = localKey(d);
      buckets.set(key, {
        date: formatDate(d),
        violations: 0,
        resolutions: 0,
        active: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    }

    // Populate violations/resolutions from drift alerts
    for (const alert of alertData.alerts) {
      const ts = new Date(alert.timestamp);
      if (ts < cutoff) continue;
      const key = localKey(ts);
      const bucket = buckets.get(key);
      if (!bucket) continue;

      if (alert.type === "new_violation") {
        bucket.violations++;
        const sev = alert.severity?.toLowerCase();
        if (sev === "critical") bucket.critical++;
        else if (sev === "high") bucket.high++;
        else if (sev === "medium") bucket.medium++;
        else if (sev === "low") bucket.low++;
      } else if (alert.type === "resolution") {
        bucket.resolutions++;
      }
    }

    const points = Array.from(buckets.values());

    // Find the first day in the period that has any event activity.
    // Days before this are "silent" — no drift events fired — so
    // we should not propagate the pre-existing baseline backward
    // into them (that would show a confusing non-zero default).
    const firstActiveIdx = points.findIndex(
      (pt) => pt.violations > 0 || pt.resolutions > 0,
    );

    // Anchor today's active count to the compliance API (ground truth).
    // Scans write directly to DynamoDB without creating drift events, so
    // computing forward from drift events alone diverges from the real count.
    // Reconstruct backwards so today always matches the dashboard.
    const todayActive = complianceData?.failed ?? 0;
    points[points.length - 1].active = todayActive;
    for (let i = points.length - 2; i >= 0; i--) {
      const next = points[i + 1];
      points[i].active = Math.max(
        0,
        next.active - next.violations + next.resolutions,
      );
    }

    // Zero out days before any activity so the chart starts at 0
    // rather than showing the pre-existing violation baseline
    // (violations in DynamoDB from before the selected period).
    if (firstActiveIdx > 0) {
      for (let i = 0; i < firstActiveIdx; i++) {
        points[i].active = 0;
      }
    }

    return points;
  }, [alertData, complianceData, days]);

  return {
    trends,
    isLoading: alertsLoading || compLoading,
    error: alertsError || compError,
  };
}
