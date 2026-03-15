import {
  renderHook,
  act,
} from "@testing-library/react";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { AlertProvider } from "@/context/AlertContext";
import { useWebSocket } from "../useWebSocket";

// Mock WebSocket class
let mockWsInstances: MockWs[] = [];

interface MockWs {
  url: string;
  readyState: number;
  onopen: ((ev: Event) => void) | null;
  onmessage:
    | ((ev: MessageEvent) => void)
    | null;
  onclose: (() => void) | null;
  onerror: (() => void) | null;
  send: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
}

class MockWebSocket implements MockWs {
  static readonly OPEN = 1;
  static readonly CLOSED = 3;

  url: string;
  readyState = 0;
  onopen: ((ev: Event) => void) | null = null;
  onmessage:
    | ((ev: MessageEvent) => void)
    | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  send = vi.fn();
  close = vi.fn().mockImplementation(() => {
    this.readyState = 3;
  });

  constructor(url: string) {
    this.url = url;
    mockWsInstances.push(this);
  }
}

const originalWebSocket = globalThis.WebSocket;

beforeEach(() => {
  vi.useFakeTimers();
  mockWsInstances = [];
  globalThis.WebSocket =
    MockWebSocket as unknown as typeof WebSocket;
  // Add OPEN constant to globalThis.WebSocket
  (globalThis.WebSocket as unknown as { OPEN: number })
    .OPEN = 1;
  localStorage.clear();
});

afterEach(() => {
  vi.useRealTimers();
  globalThis.WebSocket = originalWebSocket;
});

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
        <AlertProvider>{children}</AlertProvider>
      </QueryClientProvider>
    );
  };
}

describe("useWebSocket", () => {
  it("creates WebSocket connection on mount", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    expect(mockWsInstances).toHaveLength(1);
    expect(mockWsInstances[0].url).toContain(
      "/v1/events",
    );
    expect(mockWsInstances[0].url).not.toContain(
      "token=",
    );
  });

  it("starts ping interval on open", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    const ws = mockWsInstances[0];
    ws.readyState = 1;
    act(() => {
      ws.onopen?.({} as Event);
    });

    // Advance past the 30s ping interval
    act(() => {
      vi.advanceTimersByTime(30_000);
    });

    expect(ws.send).toHaveBeenCalledWith("ping");
  });

  it("handles JSON messages", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    const ws = mockWsInstances[0];
    ws.readyState = 1;
    act(() => {
      ws.onopen?.({} as Event);
    });

    act(() => {
      ws.onmessage?.({
        data: JSON.stringify({
          type: "violation_new",
          check_id: "s3_01",
        }),
      } as MessageEvent);
    });

    // No error thrown — message processed
    expect(ws.readyState).toBe(1);
  });

  it("ignores pong messages", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    const ws = mockWsInstances[0];
    ws.readyState = 1;
    act(() => {
      ws.onopen?.({} as Event);
    });

    // Should not throw
    act(() => {
      ws.onmessage?.({
        data: JSON.stringify({ type: "pong" }),
      } as MessageEvent);
    });
  });

  it("ignores non-JSON messages", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    const ws = mockWsInstances[0];
    act(() => {
      ws.onmessage?.({
        data: "not-json",
      } as MessageEvent);
    });

    // No error thrown
    expect(ws.close).not.toHaveBeenCalled();
  });

  it("reconnects on close with backoff", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    expect(mockWsInstances).toHaveLength(1);

    const ws = mockWsInstances[0];
    act(() => {
      ws.onclose?.();
    });

    // 1st reconnect: 1000ms
    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(mockWsInstances).toHaveLength(2);

    // 2nd close + reconnect: 2000ms
    const ws2 = mockWsInstances[1];
    act(() => {
      ws2.onclose?.();
    });
    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    expect(mockWsInstances).toHaveLength(3);
  });

  it("closes on error", () => {
    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    });

    const ws = mockWsInstances[0];
    act(() => {
      ws.onerror?.();
    });

    expect(ws.close).toHaveBeenCalled();
  });

  it("cleans up on unmount", () => {
    const { unmount } = renderHook(
      () => useWebSocket(),
      { wrapper: createWrapper() },
    );

    const ws = mockWsInstances[0];
    ws.readyState = 1;
    act(() => {
      ws.onopen?.({} as Event);
    });

    unmount();
    expect(ws.close).toHaveBeenCalled();
  });

  it("closes ws if unmounted during onopen", () => {
    const { unmount } = renderHook(
      () => useWebSocket(),
      { wrapper: createWrapper() },
    );

    const ws = mockWsInstances[0];

    // Unmount first, then simulate onopen
    unmount();
    act(() => {
      ws.onopen?.({} as Event);
    });

    expect(ws.close).toHaveBeenCalled();
  });
});
