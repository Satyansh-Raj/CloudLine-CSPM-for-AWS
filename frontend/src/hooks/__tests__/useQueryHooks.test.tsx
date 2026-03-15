import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { useCompliance } from "../useCompliance";
import { useRiskSummary } from "../useRiskSummary";
import { useViolations } from "../useViolations";
import { useDriftAlerts } from "../useDriftAlerts";

vi.mock("@/api", () => ({
  getComplianceScore: vi.fn().mockResolvedValue({
    overall_score: 78.5,
    domains: [],
  }),
  getRiskSummary: vi.fn().mockResolvedValue({
    total: 10,
    critical: 2,
    high: 3,
    medium: 3,
    low: 2,
    highest: [],
  }),
  getViolations: vi.fn().mockResolvedValue([
    {
      check_id: "s3_01",
      status: "alarm",
      severity: "critical",
    },
  ]),
  getDriftAlerts: vi.fn().mockResolvedValue({
    alerts: [
      {
        type: "new_violation",
        check_id: "s3_01",
        severity: "critical",
      },
    ],
  }),
}));

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

describe("useCompliance", () => {
  it("fetches compliance score", async () => {
    const { result } = renderHook(() => useCompliance(), {
      wrapper: createWrapper(),
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.overall_score).toBe(78.5);
  });
});

describe("useRiskSummary", () => {
  it("fetches risk summary", async () => {
    const { result } = renderHook(
      () => useRiskSummary(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.total).toBe(10);
    expect(result.current.data?.critical).toBe(2);
  });
});

describe("useViolations", () => {
  it("fetches violations", async () => {
    const { result } = renderHook(
      () => useViolations(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data).toHaveLength(1);
    expect(result.current.data?.[0].check_id).toBe(
      "s3_01",
    );
  });
});

describe("useDriftAlerts", () => {
  it("fetches drift alerts", async () => {
    const { result } = renderHook(
      () => useDriftAlerts(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.alerts).toHaveLength(1);
  });
});
