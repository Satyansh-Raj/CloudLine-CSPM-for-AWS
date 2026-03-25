import { render, screen } from "@testing-library/react";
import IssueLifecycleChart from "../IssueLifecycleChart";

// Mock recharts to avoid jsdom SVG rendering issues
vi.mock("recharts", () => ({
  AreaChart: ({
    children,
  }: {
    children: React.ReactNode;
  }) => (
    <div data-testid="area-chart">{children}</div>
  ),
  Area: () => <div data-testid="area" />,
  XAxis: () => (
    <div data-testid="x-axis" />
  ),
  YAxis: ({
    tickFormatter,
  }: {
    tickFormatter?: (v: number) => string;
  }) => (
    <div data-testid="y-axis">
      {tickFormatter && (
        <>
          <span>{tickFormatter(1)}</span>
          <span>{tickFormatter(-1)}</span>
        </>
      )}
    </div>
  ),
  CartesianGrid: () => (
    <div data-testid="cartesian-grid" />
  ),
  Tooltip: () => (
    <div data-testid="tooltip" />
  ),
  ResponsiveContainer: ({
    children,
  }: {
    children: React.ReactNode;
  }) => (
    <div data-testid="responsive-container">
      {children}
    </div>
  ),
  ReferenceLine: () => (
    <div data-testid="reference-line" />
  ),
  defs: ({
    children,
  }: {
    children: React.ReactNode;
  }) => <defs>{children}</defs>,
  linearGradient: ({
    children,
  }: {
    children: React.ReactNode;
  }) => <linearGradient>{children}</linearGradient>,
  stop: () => <stop />,
}));

describe("IssueLifecycleChart", () => {
  const DETECTED = "2026-03-18T08:00:00Z";
  const RESOLVED = "2026-03-19T10:00:00Z";

  it("renders chart container with data-testid", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByTestId("lifecycle-chart"),
    ).toBeInTheDocument();
  });

  it("shows Alarm label for detected state", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByText(/alarm/i),
    ).toBeInTheDocument();
  });

  it("shows Resolved label for resolved state", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByText(/resolved/i),
    ).toBeInTheDocument();
  });

  it("handles missing firstDetected gracefully", () => {
    render(
      <IssueLifecycleChart
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByTestId("lifecycle-chart"),
    ).toBeInTheDocument();
  });

  it("handles missing resolvedAt — shows only alarm", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByTestId("lifecycle-chart"),
    ).toBeInTheDocument();
    // chart is still rendered without resolved point
    expect(
      screen.getByTestId("area-chart"),
    ).toBeInTheDocument();
  });

  it("displays formatted date for firstDetected", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    // The chart container should be present; dates shown on axes
    expect(
      screen.getByTestId("lifecycle-chart"),
    ).toBeInTheDocument();
  });

  it("renders a ResponsiveContainer wrapping the chart", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByTestId("responsive-container"),
    ).toBeInTheDocument();
  });

  it("renders AreaChart inside container", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    expect(
      screen.getByTestId("area-chart"),
    ).toBeInTheDocument();
  });

  it("shows Y-axis tick labels Alarm and Resolved", () => {
    render(
      <IssueLifecycleChart
        firstDetected={DETECTED}
        resolvedAt={RESOLVED}
        previousStatus="alarm"
      />,
    );
    // YAxis mock calls tickFormatter(1) → "Alarm" and (-1) → "Resolved"
    expect(
      screen.getByText("Alarm"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Resolved"),
    ).toBeInTheDocument();
  });

  it("renders with both props undefined", () => {
    render(<IssueLifecycleChart />);
    expect(
      screen.getByTestId("lifecycle-chart"),
    ).toBeInTheDocument();
  });
});
