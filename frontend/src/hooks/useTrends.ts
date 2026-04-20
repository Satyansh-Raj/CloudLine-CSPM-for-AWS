import { useMemo } from "react";
import { useDriftAlerts } from "./useDriftAlerts";
import { useTrendsHistory } from "./useTrendsHistory";

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
  const since = daysAgo(days).toISOString();
  const sinceDateOnly = since.slice(0, 10);

  const {
    data: alertData,
    isLoading: alertsLoading,
    error: alertsError,
  } = useDriftAlerts({
    limit: 1000,
    account_id: accountId || undefined,
    since,
  });
  // All-time alarm states for this account — used to
  // anchor today's active count. Uses the same GSI
  // scan+filter path as alertData so account isolation
  // is guaranteed, bypassing the compliance endpoint's
  // per-region query which can miss cross-region IAM.
  const { data: allAlertsData } = useDriftAlerts({
    limit: 1000,
    account_id: accountId || undefined,
  });
  const { snapshots } = useTrendsHistory(accountId, sinceDateOnly);

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

    // Populate violations/resolutions — raw per-resource counts.
    // "New Violations" shows total resource-level violations triggered.
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
    const firstActiveIdx = points.findIndex(
      (pt) => pt.violations > 0 || pt.resolutions > 0,
    );

    // Count unique active policy violations by check_id.
    // Multiple resources can fail the same check (e.g. 4 CloudTrail
    // trails all missing insights) — count the check once, not once
    // per resource, so the number matches the violations page.
    const todayActive = allAlertsData?.alerts
      ? new Set(
          allAlertsData.alerts
            .filter((a) => a.current_status === "alarm")
            .map((a) => a.check_id),
        ).size
      : 0;
    points[points.length - 1].active = todayActive;
    for (let i = points.length - 2; i >= 0; i--) {
      const next = points[i + 1];
      points[i].active = Math.max(
        0,
        next.active - next.violations + next.resolutions,
      );
    }

    // Override reconstructed values with snapshot ground truth
    // for each day that was actually scanned. Snapshots record
    // the real active-violation count at scan time, bypassing
    // the last_evaluated timestamp overwrite problem.
    const snapshotMap = new Map(snapshots.map((s) => [s.date, s]));
    const bucketKeys = Array.from(buckets.keys());
    bucketKeys.forEach((key, idx) => {
      const snap = snapshotMap.get(key);
      if (snap) {
        points[idx].active = snap.active;
      }
    });
    // Always keep today pinned to live compliance data.
    points[points.length - 1].active = todayActive;

    // Zero out days before any activity.
    if (firstActiveIdx > 0) {
      for (let i = 0; i < firstActiveIdx; i++) {
        points[i].active = 0;
      }
    }

    return points;
  }, [alertData, allAlertsData, snapshots, days]);

  return {
    trends,
    isLoading: alertsLoading,
    error: alertsError,
  };
}
