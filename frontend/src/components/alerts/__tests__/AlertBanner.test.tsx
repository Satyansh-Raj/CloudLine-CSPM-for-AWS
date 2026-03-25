import {
  render,
  screen,
  act,
} from "@testing-library/react";
import { AlertProvider } from "@/context/AlertContext";
import { useAlerts } from "@/hooks/useAlerts";
import AlertBanner from "../AlertBanner";
import type { WsMessage } from "@/types";

const mockMsg: WsMessage = {
  type: "violation_new",
  data: {
    check_id: "ec2_no_open_ssh",
    resource_arn: "arn:aws:ec2:::i-1234",
    previous_status: "ok",
    current_status: "alarm",
    severity: "high",
    risk_score: 75,
    trigger_event: "RunInstances",
    timestamp: "2026-01-01T00:00:00Z",
    reason: "No IMDSv2",
    account_id: "123456789012",
    region: "us-east-1",
  },
};

function Trigger() {
  const { addAlert } = useAlerts();
  return (
    <button onClick={() => addAlert(mockMsg)}>
      trigger
    </button>
  );
}

function renderBanner() {
  return render(
    <AlertProvider>
      <Trigger />
      <AlertBanner />
    </AlertProvider>,
  );
}

describe("AlertBanner", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders nothing when no toasts", () => {
    const { container } = renderBanner();
    expect(
      container.querySelector('[role="alert"]'),
    ).toBeNull();
  });

  it("shows toast when alert is added", () => {
    renderBanner();
    act(() => screen.getByText("trigger").click());

    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(
      screen.getByText("ec2_no_open_ssh"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("New Violation"),
    ).toBeInTheDocument();
  });

  it("shows risk score", () => {
    renderBanner();
    act(() => screen.getByText("trigger").click());

    expect(
      screen.getByText("Risk: 75"),
    ).toBeInTheDocument();
  });

  it("auto-dismisses after 5 seconds", () => {
    renderBanner();
    act(() => screen.getByText("trigger").click());

    expect(screen.getByRole("alert")).toBeInTheDocument();

    act(() => vi.advanceTimersByTime(5_000));

    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("dismisses on close button click", () => {
    renderBanner();
    act(() => screen.getByText("trigger").click());

    const dismiss = screen.getByLabelText("Dismiss");
    act(() => dismiss.click());

    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows resolution type label", () => {
    const resolved: WsMessage = {
      ...mockMsg,
      type: "violation_resolved",
    };

    function ResolveTrigger() {
      const { addAlert } = useAlerts();
      return (
        <button onClick={() => addAlert(resolved)}>
          resolve
        </button>
      );
    }

    render(
      <AlertProvider>
        <ResolveTrigger />
        <AlertBanner />
      </AlertProvider>,
    );

    act(() => screen.getByText("resolve").click());
    expect(
      screen.getByText("Resolved"),
    ).toBeInTheDocument();
  });
});
