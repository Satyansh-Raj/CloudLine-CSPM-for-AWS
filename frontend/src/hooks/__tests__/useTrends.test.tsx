import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { useTrends } from "../useTrends";
import type { Period } from "../useTrends";

vi.mock("@/api", () => ({
  getDriftAlerts: vi.fn(),
  getComplianceScore: vi.fn(),
}));

import { getDriftAlerts, getComplianceScore } from "@/api";

const mockGetDriftAlerts = vi.mocked(getDriftAlerts);
const mockGetComplianceScore = vi.mocked(getComplianceScore);

function createWrapper() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
    },
  });
  return function Wrapper({
    children,
  }: {
    children: ReactNode;
  }) {
    return (
      <QueryClientProvider client={qc}>
        {children}
      </QueryClientProvider>
    );
  };
}

function localDateStr(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function todayIso(): string {
  return localDateStr(new Date());
}

function daysAgoIso(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return localDateStr(d);
}

describe("useTrends", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: no active violations from compliance API
    mockGetComplianceScore.mockResolvedValue({
      failed: 0,
      passed: 0,
      total_checks: 0,
      errors: 0,
      skipped: 0,
      score_percent: 100,
      by_domain: {},
      by_severity: {},
    } as never);
  });

  it("returns empty trends when no data", async () => {
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [],
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );
    expect(result.current.trends).toHaveLength(7);
    expect(
      result.current.trends.every(
        (t) => t.violations === 0,
      ),
    ).toBe(true);
  });

  it("returns loading state initially", () => {
    mockGetDriftAlerts.mockReturnValue(
      new Promise(() => {}),
    );
    mockGetComplianceScore.mockReturnValue(
      new Promise(() => {}),
    );

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    expect(result.current.isLoading).toBe(true);
  });

  it("creates correct number of buckets for each period", async () => {
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [],
    } as never);

    const periods: Period[] = ["7d", "30d", "90d"];

    for (const period of periods) {
      const { result } = renderHook(
        () => useTrends(period),
        { wrapper: createWrapper() },
      );

      await waitFor(() =>
        expect(result.current.isLoading).toBe(false),
      );

      const expected = parseInt(period);
      expect(result.current.trends).toHaveLength(
        expected,
      );
    }
  });

  it("counts violations and resolutions", async () => {
    const today = todayIso();
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [
        {
          type: "new_violation",
          severity: "critical",
          timestamp: `${today}T10:00:00Z`,
          check_id: "C1",
        },
        {
          type: "new_violation",
          severity: "high",
          timestamp: `${today}T11:00:00Z`,
          check_id: "C2",
        },
        {
          type: "resolution",
          severity: "medium",
          timestamp: `${today}T12:00:00Z`,
          check_id: "C3",
        },
      ],
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );

    const todayBucket = result.current.trends.find(
      (t) => t.violations > 0 || t.resolutions > 0,
    );
    expect(todayBucket).toBeDefined();
    expect(todayBucket?.violations).toBe(2);
    expect(todayBucket?.resolutions).toBe(1);
  });

  it("counts severity categories", async () => {
    const today = todayIso();
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [
        {
          type: "new_violation",
          severity: "critical",
          timestamp: `${today}T10:00:00Z`,
          check_id: "C1",
        },
        {
          type: "new_violation",
          severity: "HIGH",
          timestamp: `${today}T10:30:00Z`,
          check_id: "C2",
        },
        {
          type: "new_violation",
          severity: "medium",
          timestamp: `${today}T11:00:00Z`,
          check_id: "C3",
        },
        {
          type: "new_violation",
          severity: "low",
          timestamp: `${today}T11:30:00Z`,
          check_id: "C4",
        },
      ],
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );

    const todayBucket = result.current.trends.find(
      (t) => t.critical > 0,
    );
    expect(todayBucket?.critical).toBe(1);
    expect(todayBucket?.high).toBe(1);
    expect(todayBucket?.medium).toBe(1);
    expect(todayBucket?.low).toBe(1);
  });

  it("excludes alerts outside period", async () => {
    const old = daysAgoIso(10);
    const recent = todayIso();
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [
        {
          type: "new_violation",
          severity: "critical",
          timestamp: `${old}T10:00:00Z`,
          check_id: "C1",
        },
        {
          type: "new_violation",
          severity: "high",
          timestamp: `${recent}T10:00:00Z`,
          check_id: "C2",
        },
      ],
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );

    const total = result.current.trends.reduce(
      (sum, t) => sum + t.violations,
      0,
    );
    // Only the recent one should count
    expect(total).toBe(1);
  });

  it("anchors today active count to compliance API failed value", async () => {
    const today = todayIso();
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [
        {
          type: "new_violation",
          severity: "high",
          timestamp: `${today}T10:00:00Z`,
          check_id: "C1",
        },
        {
          type: "resolution",
          severity: "high",
          timestamp: `${today}T11:00:00Z`,
          check_id: "C2",
        },
      ],
    } as never);
    // Compliance API says 36 active — should override event-computed value
    mockGetComplianceScore.mockResolvedValue({
      failed: 36,
      passed: 0,
      total_checks: 36,
      errors: 0,
      skipped: 0,
      score_percent: 0,
      by_domain: {},
      by_severity: {},
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );

    const last = result.current.trends[result.current.trends.length - 1];
    expect(last.active).toBe(36);
  });

  it("handles error state", async () => {
    mockGetDriftAlerts.mockRejectedValue(
      new Error("fail"),
    );

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.error).toBeTruthy(),
    );
  });

  it("returns empty array before data loads", async () => {
    mockGetDriftAlerts.mockResolvedValue({
      alerts: undefined,
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );
    expect(result.current.trends).toEqual([]);
  });

  it("formats dates as MM/DD", async () => {
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [],
    } as never);

    const { result } = renderHook(
      () => useTrends("7d"),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isLoading).toBe(false),
    );

    for (const point of result.current.trends) {
      expect(point.date).toMatch(/^\d{2}\/\d{2}$/);
    }
  });
});
