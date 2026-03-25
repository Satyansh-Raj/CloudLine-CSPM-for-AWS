import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { useExecutiveSummary } from "../useExecutiveSummary";

vi.mock("@/api", () => ({
  getExecutiveSummary: vi.fn().mockResolvedValue({
    total_active: 5,
    total_resolved: 10,
    resolution_rate: 66.7,
    by_domain: {
      identity_access: {
        active: 2,
        resolved: 3,
        total_checks: 50,
        score_percent: 96,
      },
    },
    by_severity: {
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
    },
    trend: {
      resolved_last_24h: 3,
      new_last_24h: 1,
    },
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

describe("useExecutiveSummary", () => {
  it("fetches executive summary data", async () => {
    const { result } = renderHook(
      () => useExecutiveSummary(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.total_active).toBe(5);
    expect(result.current.data?.total_resolved).toBe(10);
  });

  it("exposes resolution_rate", async () => {
    const { result } = renderHook(
      () => useExecutiveSummary(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.resolution_rate).toBe(
      66.7,
    );
  });

  it("exposes by_severity breakdown", async () => {
    const { result } = renderHook(
      () => useExecutiveSummary(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.by_severity.critical).toBe(
      1,
    );
  });

  it("exposes trend data", async () => {
    const { result } = renderHook(
      () => useExecutiveSummary(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(
      result.current.data?.trend.resolved_last_24h,
    ).toBe(3);
  });

  it("accepts region and account_id params", async () => {
    const { getExecutiveSummary } = await import("@/api");
    const { result } = renderHook(
      () =>
        useExecutiveSummary({
          region: "us-east-1",
          account_id: "123456789012",
        }),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(getExecutiveSummary).toHaveBeenCalledWith({
      region: "us-east-1",
      account_id: "123456789012",
    });
  });

  it("starts in loading state", () => {
    const { result } = renderHook(
      () => useExecutiveSummary(),
      { wrapper: createWrapper() },
    );
    expect(result.current.isLoading).toBe(true);
  });
});
