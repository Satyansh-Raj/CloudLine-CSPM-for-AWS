import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import ExecutiveSummaryPage from "../ExecutiveSummaryPage";

const mockSummary = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks/useExecutiveSummary", () => ({
  useExecutiveSummary: () => mockSummary,
}));

vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => ({
    selectedRegion: "",
    regions: ["ap-south-1", "us-east-1"],
    isLoading: false,
    setSelectedRegion: vi.fn(),
  }),
}));

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "",
    accounts: [],
    isLoading: false,
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

// Recharts mock to avoid jsdom SVG issues
vi.mock("recharts", () => ({
  BarChart: ({
    children,
  }: {
    children: React.ReactNode;
  }) => <div data-testid="bar-chart">{children}</div>,
  Bar: () => <div data-testid="bar" />,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  CartesianGrid: () => null,
  ResponsiveContainer: ({
    children,
  }: {
    children: React.ReactNode;
  }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
  PieChart: ({
    children,
  }: {
    children: React.ReactNode;
  }) => <div data-testid="pie-chart">{children}</div>,
  Pie: ({
    children,
  }: {
    children?: React.ReactNode;
  }) => <div data-testid="pie">{children}</div>,
  Cell: () => <div data-testid="cell" />,
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <ExecutiveSummaryPage />
    </MemoryRouter>,
  );
}

const FULL_DATA = {
  total_active: 15,
  total_resolved: 42,
  resolution_rate: 73.7,
  by_domain: {
    identity_access: {
      active: 3,
      resolved: 10,
      total_checks: 50,
      score_percent: 94,
    },
    data_protection: {
      active: 5,
      resolved: 8,
      total_checks: 40,
      score_percent: 87.5,
    },
  },
  by_severity: {
    critical: 2,
    high: 5,
    medium: 6,
    low: 2,
  },
  trend: {
    resolved_last_24h: 3,
    new_last_24h: 1,
  },
};

describe("ExecutiveSummaryPage", () => {
  afterEach(() => {
    mockSummary.data = null;
    mockSummary.isLoading = false;
    mockSummary.error = null;
  });

  it("shows heading", () => {
    renderPage();
    expect(
      screen.getByText("Executive Summary"),
    ).toBeInTheDocument();
  });

  it("shows loading skeleton", () => {
    mockSummary.isLoading = true;
    const { container } = renderPage();
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error state", () => {
    mockSummary.error = { message: "API error" };
    renderPage();
    expect(
      screen.getByText(/api error/i),
    ).toBeInTheDocument();
  });

  it("shows no data message when data is null", () => {
    renderPage();
    expect(
      screen.getByText(/no data available/i),
    ).toBeInTheDocument();
  });

  it("shows total_active count", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(screen.getByText("15")).toBeInTheDocument();
  });

  it("shows total_resolved count", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("shows resolution_rate percentage", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByText("73.7%"),
    ).toBeInTheDocument();
  });

  it("shows critical severity count", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    // critical count is 2
    const criticalEl = screen.getByTestId("sev-critical");
    expect(criticalEl).toBeInTheDocument();
  });

  it("renders domain compliance section", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByText(/domain compliance/i),
    ).toBeInTheDocument();
  });

  it("renders domain rows for each domain", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByText(/identity access/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/data protection/i),
    ).toBeInTheDocument();
  });

  it("renders severity breakdown section", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByTestId("severity-breakdown"),
    ).toBeInTheDocument();
  });

  it("renders trend section", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByTestId("trend-section"),
    ).toBeInTheDocument();
  });

  it("shows resolved_last_24h trend value", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByTestId("trend-resolved-24h"),
    ).toHaveTextContent("3");
  });

  it("shows new_last_24h trend value", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByTestId("trend-new-24h"),
    ).toHaveTextContent("1");
  });

  it("renders region selector", () => {
    renderPage();
    const select = screen.getByRole("combobox", {
      name: /region/i,
    });
    expect(select).toBeInTheDocument();
  });

  it("shows bar chart for domain breakdown", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getAllByTestId("bar-chart").length,
    ).toBeGreaterThanOrEqual(1);
  });

  it("handles zero resolution_rate", () => {
    mockSummary.data = {
      ...FULL_DATA,
      total_resolved: 0,
      resolution_rate: 0,
    };
    renderPage();
    expect(screen.getByText("0%")).toBeInTheDocument();
  });

  it("shows active violations label", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByText(/active violations/i),
    ).toBeInTheDocument();
  });

  it("shows resolved violations label", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByText(/resolved violations/i),
    ).toBeInTheDocument();
  });

  it("shows resolution rate label", () => {
    mockSummary.data = FULL_DATA;
    renderPage();
    expect(
      screen.getByText(/resolution rate/i),
    ).toBeInTheDocument();
  });
});
