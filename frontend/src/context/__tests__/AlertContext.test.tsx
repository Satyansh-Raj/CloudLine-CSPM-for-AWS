import { render, screen, act } from "@testing-library/react";
import { AlertProvider } from "../AlertContext";
import { useAlerts } from "@/hooks/useAlerts";
import type { WsMessage } from "@/types";

const mockMsg: WsMessage = {
  type: "violation_new",
  data: {
    check_id: "s3_01",
    resource_arn: "arn:aws:s3:::test-bucket",
    previous_status: "ok",
    current_status: "alarm",
    severity: "critical",
    risk_score: 90,
    trigger_event: "PutBucketPolicy",
    timestamp: "2026-01-01T00:00:00Z",
    reason: "Public access",
    account_id: "123456789012",
    region: "us-east-1",
  },
};

function AlertConsumer() {
  const ctx = useAlerts();
  return (
    <div>
      <span data-testid="count">{ctx.alerts.length}</span>
      <span data-testid="toasts">{ctx.toasts.length}</span>
      <span data-testid="unread">{ctx.unreadCount}</span>
      <span data-testid="status">{ctx.status}</span>
      <button onClick={() => ctx.addAlert(mockMsg)}>
        add
      </button>
      <button onClick={ctx.markAllRead}>readAll</button>
      <button onClick={ctx.clearAlerts}>clear</button>
      <button onClick={() => ctx.setStatus("connected")}>
        connect
      </button>
      {ctx.alerts.map((a) => (
        <div key={a.id} data-testid="alert">
          <span>{a.data.check_id}</span>
          <button onClick={() => ctx.markRead(a.id)}>
            read-{a.id}
          </button>
          <button onClick={() => ctx.dismissToast(a.id)}>
            dismiss-{a.id}
          </button>
        </div>
      ))}
    </div>
  );
}

function renderAlerts() {
  return render(
    <AlertProvider>
      <AlertConsumer />
    </AlertProvider>,
  );
}

describe("AlertContext", () => {
  it("starts with empty state", () => {
    renderAlerts();
    expect(screen.getByTestId("count")).toHaveTextContent(
      "0",
    );
    expect(
      screen.getByTestId("toasts"),
    ).toHaveTextContent("0");
    expect(
      screen.getByTestId("unread"),
    ).toHaveTextContent("0");
    expect(
      screen.getByTestId("status"),
    ).toHaveTextContent("disconnected");
  });

  it("adds an alert and toast", () => {
    renderAlerts();
    act(() => screen.getByText("add").click());

    expect(screen.getByTestId("count")).toHaveTextContent(
      "1",
    );
    expect(
      screen.getByTestId("toasts"),
    ).toHaveTextContent("1");
    expect(
      screen.getByTestId("unread"),
    ).toHaveTextContent("1");
    expect(
      screen.getByText("s3_01"),
    ).toBeInTheDocument();
  });

  it("marks single alert as read", () => {
    renderAlerts();
    act(() => screen.getByText("add").click());

    expect(
      screen.getByTestId("unread"),
    ).toHaveTextContent("1");

    const readBtn = screen.getAllByRole("button").find(
      (b) => b.textContent?.startsWith("read-ws-"),
    )!;
    act(() => readBtn.click());

    expect(
      screen.getByTestId("unread"),
    ).toHaveTextContent("0");
  });

  it("marks all as read", () => {
    renderAlerts();
    act(() => screen.getByText("add").click());
    act(() => screen.getByText("add").click());

    expect(
      screen.getByTestId("unread"),
    ).toHaveTextContent("2");

    act(() => screen.getByText("readAll").click());

    expect(
      screen.getByTestId("unread"),
    ).toHaveTextContent("0");
  });

  it("clears all alerts", () => {
    renderAlerts();
    act(() => screen.getByText("add").click());
    act(() => screen.getByText("clear").click());

    expect(screen.getByTestId("count")).toHaveTextContent(
      "0",
    );
    expect(
      screen.getByTestId("toasts"),
    ).toHaveTextContent("0");
  });

  it("sets connection status", () => {
    renderAlerts();
    act(() => screen.getByText("connect").click());

    expect(
      screen.getByTestId("status"),
    ).toHaveTextContent("connected");
  });

  it("caps toasts at 5", () => {
    renderAlerts();
    for (let i = 0; i < 7; i++) {
      act(() => screen.getByText("add").click());
    }

    expect(
      screen.getByTestId("toasts"),
    ).toHaveTextContent("5");
    expect(screen.getByTestId("count")).toHaveTextContent(
      "7",
    );
  });

  it("ignores messages without data", () => {
    renderAlerts();
    // addAlert with no data — done via custom consumer
    const noDataMsg: WsMessage = {
      type: "pong",
    };

    function NoDataConsumer() {
      const ctx = useAlerts();
      return (
        <button onClick={() => ctx.addAlert(noDataMsg)}>
          addNoData
        </button>
      );
    }

    const { unmount } = render(
      <AlertProvider>
        <NoDataConsumer />
      </AlertProvider>,
    );
    act(() => screen.getByText("addNoData").click());
    unmount();
  });

  it("dismisses a toast", () => {
    renderAlerts();
    act(() => screen.getByText("add").click());

    expect(
      screen.getByTestId("toasts"),
    ).toHaveTextContent("1");

    const dismissBtn = screen
      .getAllByRole("button")
      .find((b) =>
        b.textContent?.startsWith("dismiss-ws-"),
      )!;
    act(() => dismissBtn.click());

    expect(
      screen.getByTestId("toasts"),
    ).toHaveTextContent("0");
  });
});
