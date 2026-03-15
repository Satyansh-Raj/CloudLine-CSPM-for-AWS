import { render, screen } from "@testing-library/react";
import DashboardPage from "../DashboardPage";

const mockCompliance = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};
const mockRisk = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useCompliance: () => mockCompliance,
  useRiskSummary: () => mockRisk,
}));

vi.mock("@/components/dashboard", () => ({
  ComplianceScoreDonut: () => (
    <div data-testid="donut" />
  ),
  DomainDonut: () => <div data-testid="domain" />,
  SeverityBar: () => <div data-testid="severity" />,
  RiskCards: () => <div data-testid="risk" />,
  KpiCards: () => <div data-testid="kpi" />,
  ViolationAreaChart: () => (
    <div data-testid="area-chart" />
  ),
  TopViolationsTable: () => (
    <div data-testid="top-violations" />
  ),
  DomainPieChart: () => (
    <div data-testid="domain-pie" />
  ),
}));

describe("DashboardPage", () => {
  afterEach(() => {
    mockCompliance.data = null;
    mockCompliance.isLoading = false;
    mockCompliance.error = null;
    mockRisk.data = null;
    mockRisk.isLoading = false;
    mockRisk.error = null;
  });

  it("shows loading skeleton", () => {
    mockCompliance.isLoading = true;
    const { container } = render(<DashboardPage />);
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error banner", () => {
    mockCompliance.error = { message: "Network fail" };
    render(<DashboardPage />);
    expect(
      screen.getByText(/network fail/i),
    ).toBeInTheDocument();
  });

  it("shows no data message", () => {
    render(<DashboardPage />);
    expect(
      screen.getByText(/no scan data yet/i),
    ).toBeInTheDocument();
  });

  it("renders charts when data is loaded", () => {
    mockCompliance.data = {
      score_percent: 85,
      passed: 17,
      failed: 3,
      errors: 0,
      skipped: 0,
      total_checks: 20,
      by_domain: {},
      by_severity: {},
    };
    mockRisk.data = {
      total_scored: 20,
      by_category: { critical: 1 },
      highest_risk: [],
    };
    render(<DashboardPage />);
    expect(
      screen.getByTestId("donut"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("severity"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("kpi"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("domain-pie"),
    ).toBeInTheDocument();
  });
});
