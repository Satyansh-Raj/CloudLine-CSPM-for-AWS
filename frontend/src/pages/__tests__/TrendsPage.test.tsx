import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import TrendsPage from "../TrendsPage";

const mockTrends = {
  trends: [] as unknown[],
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useTrends: () => mockTrends,
}));

vi.mock("@/components/trends", () => ({
  PeriodSelector: ({
    value,
    onChange,
  }: {
    value: string;
    onChange: (v: string) => void;
  }) => (
    <div data-testid="period">
      <button onClick={() => onChange("30d")}>
        {value}
      </button>
    </div>
  ),
  TrendLineChart: () => (
    <div data-testid="trend-line" />
  ),
  SeverityTrendChart: () => (
    <div data-testid="severity-trend" />
  ),
}));

describe("TrendsPage", () => {
  afterEach(() => {
    mockTrends.trends = [];
    mockTrends.isLoading = false;
    mockTrends.error = null;
  });

  it("shows heading", () => {
    render(<TrendsPage />);
    expect(
      screen.getByText("Trends"),
    ).toBeInTheDocument();
  });

  it("shows loading state", () => {
    mockTrends.isLoading = true;
    const { container } = render(<TrendsPage />);
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error state", () => {
    mockTrends.error = { message: "Trend fail" };
    render(<TrendsPage />);
    expect(
      screen.getByText(/trend fail/i),
    ).toBeInTheDocument();
  });

  it("renders charts when data loaded", () => {
    mockTrends.trends = [
      {
        date: "01/01",
        violations: 5,
        resolutions: 3,
      },
    ];
    render(<TrendsPage />);
    expect(
      screen.getByTestId("trend-line"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("severity-trend"),
    ).toBeInTheDocument();
  });

  it("renders period selector", () => {
    render(<TrendsPage />);
    expect(
      screen.getByTestId("period"),
    ).toBeInTheDocument();
  });
});
