import { vi } from "vitest";

const mockGetComplianceScore = vi.fn();

vi.mock("@/api", () => ({
  getComplianceScore: (...args: unknown[]) =>
    mockGetComplianceScore(...args),
}));

vi.mock("@tanstack/react-query", () => ({
  useQuery: vi.fn(({ queryKey, queryFn }) => ({
    queryKey,
    queryFn,
    data: undefined,
    isLoading: false,
  })),
}));

import { useQuery } from "@tanstack/react-query";
import { useCompliance } from "../useCompliance";

const mockUseQuery = vi.mocked(useQuery);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("useCompliance", () => {
  it("uses compliance as base query key when no accountId", () => {
    useCompliance();
    const call = mockUseQuery.mock.calls[0][0];
    expect(call.queryKey).toEqual(["compliance", undefined]);
  });

  it("includes accountId in queryKey when provided", () => {
    useCompliance("111111111111");
    const call = mockUseQuery.mock.calls[0][0];
    expect(call.queryKey).toEqual(["compliance", "111111111111"]);
  });

  it("calls getComplianceScore with accountId in queryFn", async () => {
    mockGetComplianceScore.mockResolvedValue({ score_percent: 80 });
    useCompliance("111111111111");
    const call = mockUseQuery.mock.calls[0][0];
    await call.queryFn();
    expect(mockGetComplianceScore).toHaveBeenCalledWith("111111111111");
  });

  it("calls getComplianceScore with undefined when no accountId", async () => {
    mockGetComplianceScore.mockResolvedValue({ score_percent: 80 });
    useCompliance();
    const call = mockUseQuery.mock.calls[0][0];
    await call.queryFn();
    expect(mockGetComplianceScore).toHaveBeenCalledWith(undefined);
  });
});
