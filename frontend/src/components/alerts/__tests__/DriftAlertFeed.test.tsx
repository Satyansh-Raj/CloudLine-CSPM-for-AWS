import {
  render,
  screen,
  act,
} from "@testing-library/react";
import { AlertProvider } from "@/context/AlertContext";
import { useAlerts } from "@/hooks/useAlerts";
import DriftAlertFeed from "../DriftAlertFeed";
import type { WsMessage } from "@/types";

const mockMsg: WsMessage = {
  type: "violation_new",
  data: {
    check_id: "s3_block_public_acls",
    resource_arn: "arn:aws:s3:::bucket-1",
    previous_status: "ok",
    current_status: "alarm",
    severity: "critical",
    risk_score: 95,
    trigger_event: "PutBucketPolicy",
    timestamp: "2026-01-01T00:00:00Z",
    reason: "Public access",
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

function renderFeed() {
  return render(
    <AlertProvider>
      <Trigger />
      <DriftAlertFeed />
    </AlertProvider>,
  );
}

describe("DriftAlertFeed", () => {
  it("shows empty state", () => {
    renderFeed();
    expect(
      screen.getByText("No alerts yet"),
    ).toBeInTheDocument();
  });

  it("shows Live Alerts heading", () => {
    renderFeed();
    expect(
      screen.getByText("Live Alerts"),
    ).toBeInTheDocument();
  });

  it("shows alert after trigger", () => {
    renderFeed();
    act(() => screen.getByText("trigger").click());

    expect(
      screen.getByText("s3_block_public_acls"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("No alerts yet"),
    ).not.toBeInTheDocument();
  });

  it("shows Mark all read button when alerts exist", () => {
    renderFeed();
    act(() => screen.getByText("trigger").click());

    expect(
      screen.getByText("Mark all read"),
    ).toBeInTheDocument();
  });

  it("hides Mark all read when no alerts", () => {
    renderFeed();
    expect(
      screen.queryByText("Mark all read"),
    ).not.toBeInTheDocument();
  });

  it("marks alert as read on click", () => {
    renderFeed();
    act(() => screen.getByText("trigger").click());

    const alertBtn = screen.getByText("s3_block_public_acls")
      .closest("button")!;
    act(() => alertBtn.click());

    // Unread styling removed (no bg-blue highlight)
    expect(alertBtn.className).not.toContain(
      "bg-blue-50",
    );
  });
});
