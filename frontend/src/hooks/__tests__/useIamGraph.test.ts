import { vi } from "vitest";

const mockGetIamGraph = vi.fn();

vi.mock("@/api", () => ({
  getIamGraph: (...args: unknown[]) => mockGetIamGraph(...args),
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
import { useIamGraph } from "../useIamGraph";

const mockUseQuery = vi.mocked(useQuery);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("useIamGraph", () => {
  it("uses iam-graph as base query key when no accountId", () => {
    useIamGraph();
    const call = mockUseQuery.mock.calls[0][0];
    expect(call.queryKey).toEqual(["iam-graph", undefined]);
  });

  it("includes accountId in queryKey when provided", () => {
    useIamGraph("111111111111");
    const call = mockUseQuery.mock.calls[0][0];
    expect(call.queryKey).toEqual(["iam-graph", "111111111111"]);
  });

  it("calls getIamGraph with accountId in queryFn", async () => {
    mockGetIamGraph.mockResolvedValue({ account_id: "111", users: [] });
    useIamGraph("111111111111");
    const call = mockUseQuery.mock.calls[0][0];
    await call.queryFn();
    expect(mockGetIamGraph).toHaveBeenCalledWith("111111111111");
  });

  it("calls getIamGraph with undefined when no accountId", async () => {
    mockGetIamGraph.mockResolvedValue({ account_id: "x", users: [] });
    useIamGraph();
    const call = mockUseQuery.mock.calls[0][0];
    await call.queryFn();
    expect(mockGetIamGraph).toHaveBeenCalledWith(undefined);
  });
});
