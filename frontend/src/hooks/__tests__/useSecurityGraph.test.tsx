import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { useSecurityGraph } from "../useSecurityGraph";
import type { SecurityGraph } from "@/types/securityGraph";

/* ── Mocks ───────────────────────────────────── */

const mockGetSecurityGraph = vi.fn();

vi.mock("@/api/inventory", () => ({
  getSecurityGraph: (...args: unknown[]) =>
    mockGetSecurityGraph(...args),
}));

const mockRegion = { selectedRegion: "" };
vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => mockRegion,
}));

const mockAccount = { selectedAccount: "" };
vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => mockAccount,
}));

/* ── Helpers ─────────────────────────────────── */

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

function makeGraph(
  overrides: Partial<SecurityGraph> = {},
): SecurityGraph {
  return {
    nodes: [],
    edges: [],
    attack_paths: 0,
    total_nodes: 0,
    total_edges: 0,
    ...overrides,
  };
}

/* ── Tests ───────────────────────────────────── */

describe("useSecurityGraph", () => {
  beforeEach(() => {
    mockRegion.selectedRegion = "";
    mockAccount.selectedAccount = "";
    mockGetSecurityGraph.mockReset();
  });

  it("fetches data successfully", async () => {
    const graph = makeGraph({
      total_nodes: 5,
      total_edges: 3,
      attack_paths: 1,
    });
    mockGetSecurityGraph.mockResolvedValue(graph);

    const { result } = renderHook(
      () => useSecurityGraph(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(result.current.data?.total_nodes).toBe(5);
    expect(result.current.data?.total_edges).toBe(3);
    expect(result.current.data?.attack_paths).toBe(1);
  });

  it("passes region param when region is selected", async () => {
    mockRegion.selectedRegion = "ap-south-1";
    mockGetSecurityGraph.mockResolvedValue(makeGraph());

    const { result } = renderHook(
      () => useSecurityGraph(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(mockGetSecurityGraph).toHaveBeenCalledWith({
      region: "ap-south-1",
      account_id: undefined,
    });
  });

  it("passes account_id param when account is selected", async () => {
    mockAccount.selectedAccount = "123456789012";
    mockGetSecurityGraph.mockResolvedValue(makeGraph());

    const { result } = renderHook(
      () => useSecurityGraph(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(mockGetSecurityGraph).toHaveBeenCalledWith({
      region: undefined,
      account_id: "123456789012",
    });
  });

  it("shows loading state initially", () => {
    mockGetSecurityGraph.mockReturnValue(
      new Promise(() => {}),
    );

    const { result } = renderHook(
      () => useSecurityGraph(),
      { wrapper: createWrapper() },
    );

    expect(result.current.isLoading).toBe(true);
    expect(result.current.data).toBeUndefined();
  });

  it("exposes error state on failure", async () => {
    mockGetSecurityGraph.mockRejectedValue(
      new Error("Network error"),
    );

    const { result } = renderHook(
      () => useSecurityGraph(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isError).toBe(true),
    );
  });

  it("passes undefined for empty region/account", async () => {
    mockRegion.selectedRegion = "";
    mockAccount.selectedAccount = "";
    mockGetSecurityGraph.mockResolvedValue(makeGraph());

    const { result } = renderHook(
      () => useSecurityGraph(),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );
    expect(mockGetSecurityGraph).toHaveBeenCalledWith({
      region: undefined,
      account_id: undefined,
    });
  });
});
