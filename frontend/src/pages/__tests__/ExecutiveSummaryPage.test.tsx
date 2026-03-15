import { render, screen } from "@testing-library/react";
import ExecutiveSummaryPage from "../ExecutiveSummaryPage";

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

describe("ExecutiveSummaryPage", () => {
  afterEach(() => {
    mockCompliance.data = null;
    mockCompliance.isLoading = false;
    mockCompliance.error = null;
    mockRisk.data = null;
    mockRisk.isLoading = false;
    mockRisk.error = null;
  });

  it("shows heading", () => {
    render(<ExecutiveSummaryPage />);
    expect(
      screen.getByText("Executive Summary"),
    ).toBeInTheDocument();
  });

  it("shows loading state", () => {
    mockCompliance.isLoading = true;
    const { container } = render(
      <ExecutiveSummaryPage />,
    );
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error state", () => {
    mockCompliance.error = { message: "API error" };
    render(<ExecutiveSummaryPage />);
    expect(
      screen.getByText(/api error/i),
    ).toBeInTheDocument();
  });

  it("shows no data message", () => {
    render(<ExecutiveSummaryPage />);
    expect(
      screen.getByText(/no data available/i),
    ).toBeInTheDocument();
  });

  it("renders KPI cards with data", () => {
    mockCompliance.data = {
      score_percent: 85,
      passed: 17,
      failed: 3,
      errors: 0,
      skipped: 0,
      by_domain: {
        identity_access: {
          passed: 4,
          failed: 1,
          total: 5,
          score_percent: 80,
        },
      },
      by_severity: {},
    };
    mockRisk.data = {
      total_scored: 20,
      by_category: {
        critical: 0,
        high: 2,
        medium: 5,
        low: 8,
      },
      highest_risk: [],
    };
    render(<ExecutiveSummaryPage />);
    expect(screen.getByText("85%")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("20")).toBeInTheDocument();
  });

  it("shows At Risk when criticals exist", () => {
    mockCompliance.data = {
      score_percent: 50,
      passed: 10,
      failed: 10,
      errors: 0,
      skipped: 0,
      by_domain: {},
      by_severity: { critical: 3, high: 2, medium: 1, low: 0 },
    };
    mockRisk.data = {
      total_scored: 20,
      by_category: { critical: 3 },
      highest_risk: [],
    };
    render(<ExecutiveSummaryPage />);
    expect(
      screen.getByText("At Risk"),
    ).toBeInTheDocument();
  });
});
