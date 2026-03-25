import { render, screen } from "@testing-library/react";
import IssueHistoryChart from "../IssueHistoryChart";

// Mock recharts to avoid jsdom SVG issues
vi.mock("recharts", () => ({
  AreaChart: ({
    children,
    data,
  }: {
    children: React.ReactNode;
    data: unknown[];
  }) => (
    <div data-testid="history-area-chart" data-len={data.length}>
      {children}
    </div>
  ),
  Area: ({ dataKey }: { dataKey: string }) => (
    <div data-testid={`area-${dataKey}`} />
  ),
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
  ReferenceLine: () => <div data-testid="reference-line" />,
}));

const MULTI_HISTORY = [
  { status: "alarm", timestamp: "2026-03-01T10:00:00Z" },
  { status: "ok", timestamp: "2026-03-05T12:00:00Z" },
  { status: "alarm", timestamp: "2026-03-08T09:00:00Z" },
  { status: "ok", timestamp: "2026-03-15T14:00:00Z" },
];

describe("IssueHistoryChart", () => {
  it("renders chart container", () => {
    render(<IssueHistoryChart statusHistory={MULTI_HISTORY} />);
    expect(screen.getByTestId("issue-history-chart")).toBeInTheDocument();
  });

  it("renders responsive container", () => {
    render(<IssueHistoryChart statusHistory={MULTI_HISTORY} />);
    expect(screen.getByTestId("responsive-container")).toBeInTheDocument();
  });

  it("renders area chart with correct data length", () => {
    render(<IssueHistoryChart statusHistory={MULTI_HISTORY} />);
    const chart = screen.getByTestId("history-area-chart");
    // 4 history points + interpolated points between
    const len = Number(chart.getAttribute("data-len"));
    expect(len).toBeGreaterThanOrEqual(4);
  });

  it("renders alarm, resolved, and state areas", () => {
    render(<IssueHistoryChart statusHistory={MULTI_HISTORY} />);
    expect(screen.getByTestId("area-alarm")).toBeInTheDocument();
    expect(screen.getByTestId("area-resolved")).toBeInTheDocument();
    expect(screen.getByTestId("area-state")).toBeInTheDocument();
  });

  it("renders reference lines for alarm and ok", () => {
    render(<IssueHistoryChart statusHistory={MULTI_HISTORY} />);
    const refs = screen.getAllByTestId("reference-line");
    expect(refs.length).toBe(2);
  });

  it("handles empty history gracefully", () => {
    render(<IssueHistoryChart statusHistory={[]} />);
    expect(screen.getByTestId("issue-history-chart")).toBeInTheDocument();
    expect(screen.getByText(/no history/i)).toBeInTheDocument();
  });

  it("handles single-entry history", () => {
    render(
      <IssueHistoryChart
        statusHistory={[
          {
            status: "alarm",
            timestamp: "2026-03-01T10:00:00Z",
          },
        ]}
      />,
    );
    expect(screen.getByTestId("history-area-chart")).toBeInTheDocument();
  });

  it("renders section title", () => {
    render(<IssueHistoryChart statusHistory={MULTI_HISTORY} />);
    expect(screen.getByText("Issue History")).toBeInTheDocument();
  });
});
