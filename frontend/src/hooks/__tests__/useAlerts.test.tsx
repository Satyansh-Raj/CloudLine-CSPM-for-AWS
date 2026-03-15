import { renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { AlertProvider } from "@/context/AlertContext";
import { useAlerts } from "../useAlerts";

function wrapper({ children }: { children: ReactNode }) {
  return <AlertProvider>{children}</AlertProvider>;
}

describe("useAlerts", () => {
  it("throws outside AlertProvider", () => {
    expect(() =>
      renderHook(() => useAlerts()),
    ).toThrow(
      "useAlerts must be used within AlertProvider",
    );
  });

  it("returns alert context inside provider", () => {
    const { result } = renderHook(() => useAlerts(), {
      wrapper,
    });

    expect(result.current.alerts).toEqual([]);
    expect(result.current.toasts).toEqual([]);
    expect(result.current.unreadCount).toBe(0);
    expect(result.current.status).toBe("disconnected");
    expect(typeof result.current.addAlert).toBe(
      "function",
    );
    expect(typeof result.current.dismissToast).toBe(
      "function",
    );
    expect(typeof result.current.markRead).toBe(
      "function",
    );
    expect(typeof result.current.markAllRead).toBe(
      "function",
    );
    expect(typeof result.current.clearAlerts).toBe(
      "function",
    );
    expect(typeof result.current.setStatus).toBe(
      "function",
    );
  });
});
