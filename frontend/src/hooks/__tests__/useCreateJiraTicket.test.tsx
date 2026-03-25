import { renderHook, act, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";

const mockCreateJiraTicket = vi.fn();

vi.mock("@/api", () => ({
  createJiraTicket: (
    params: unknown,
  ) => mockCreateJiraTicket(params),
}));

const mockResponse = {
  ticket_id: "10042",
  ticket_url: "https://example.atlassian.net/browse/SEC-42",
  ticket_key: "SEC-42",
};

const testParams = {
  account_id: "123456789012",
  region: "ap-south-1",
  check_id: "s3_block_public_acls",
  resource_id: "arn:aws:s3:::my-bucket",
};

function createWrapper() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
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

describe("useCreateJiraTicket", () => {
  beforeEach(() => {
    mockCreateJiraTicket.mockReset();
  });

  it("calls createJiraTicket API with correct params", async () => {
    mockCreateJiraTicket.mockResolvedValueOnce(mockResponse);

    const { useCreateJiraTicket } = await import(
      "../useCreateJiraTicket"
    );
    const { result } = renderHook(
      () => useCreateJiraTicket(),
      { wrapper: createWrapper() },
    );

    await act(async () => {
      result.current.mutate(testParams);
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );

    expect(mockCreateJiraTicket).toHaveBeenCalledWith(
      testParams,
    );
  });

  it("returns ticket data on success", async () => {
    mockCreateJiraTicket.mockResolvedValueOnce(mockResponse);

    const { useCreateJiraTicket } = await import(
      "../useCreateJiraTicket"
    );
    const { result } = renderHook(
      () => useCreateJiraTicket(),
      { wrapper: createWrapper() },
    );

    await act(async () => {
      result.current.mutate(testParams);
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );

    expect(result.current.data).toEqual(mockResponse);
    expect(result.current.data?.ticket_key).toBe("SEC-42");
  });

  it("invalidates violations query on success", async () => {
    mockCreateJiraTicket.mockResolvedValueOnce(mockResponse);

    const qc = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: 0 },
        mutations: { retry: false },
      },
    });
    const invalidateSpy = vi.spyOn(
      qc,
      "invalidateQueries",
    );

    const { useCreateJiraTicket } = await import(
      "../useCreateJiraTicket"
    );
    const wrapper = ({
      children,
    }: {
      children: ReactNode;
    }) => (
      <QueryClientProvider client={qc}>
        {children}
      </QueryClientProvider>
    );

    const { result } = renderHook(
      () => useCreateJiraTicket(),
      { wrapper },
    );

    await act(async () => {
      result.current.mutate(testParams);
    });

    await waitFor(() =>
      expect(result.current.isSuccess).toBe(true),
    );

    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        queryKey: ["violations"],
      }),
    );
  });

  it("exposes isError and error on failure", async () => {
    const err = new Error("Jira not configured");
    mockCreateJiraTicket.mockRejectedValueOnce(err);

    const { useCreateJiraTicket } = await import(
      "../useCreateJiraTicket"
    );
    const { result } = renderHook(
      () => useCreateJiraTicket(),
      { wrapper: createWrapper() },
    );

    await act(async () => {
      result.current.mutate(testParams);
    });

    await waitFor(() =>
      expect(result.current.isError).toBe(true),
    );

    expect(result.current.error?.message).toBe(
      "Jira not configured",
    );
  });

  it("starts in idle state", async () => {
    const { useCreateJiraTicket } = await import(
      "../useCreateJiraTicket"
    );
    const { result } = renderHook(
      () => useCreateJiraTicket(),
      { wrapper: createWrapper() },
    );

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.isError).toBe(false);
    expect(result.current.data).toBeUndefined();
  });

  it("sets isPending during mutation", async () => {
    // Use a never-resolving promise to freeze in pending
    mockCreateJiraTicket.mockReturnValueOnce(
      new Promise(() => {}),
    );

    const { useCreateJiraTicket } = await import(
      "../useCreateJiraTicket"
    );
    const { result } = renderHook(
      () => useCreateJiraTicket(),
      { wrapper: createWrapper() },
    );

    act(() => {
      result.current.mutate(testParams);
    });

    // After triggering, isPending should become true
    await waitFor(() =>
      expect(result.current.isPending).toBe(true),
    );
  });
});
