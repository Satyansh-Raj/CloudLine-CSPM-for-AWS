import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import CompliancePage from "../CompliancePage";

/* ---- stable mock data ---- */

const mockFrameworksData = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

const mockFrameworkScore = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

const mockComplianceScore = {
  data: {
    total_checks: 100,
    passed: 80,
    failed: 20,
    total_violations: 20,
    errors: 0,
    skipped: 0,
    score_percent: 80,
    by_domain: {},
    by_severity: {},
    by_framework: {
      cis_aws: {
        score_percent: 84.44,
        total_controls: 45,
        compliant: 38,
        non_compliant: 7,
      },
      nist_800_53: {
        score_percent: 76.5,
        total_controls: 60,
        compliant: 46,
        non_compliant: 14,
      },
      pci_dss: {
        score_percent: 91.0,
        total_controls: 33,
        compliant: 30,
        non_compliant: 3,
      },
      hipaa: {
        score_percent: 68.0,
        total_controls: 25,
        compliant: 17,
        non_compliant: 8,
      },
      soc2: {
        score_percent: 88.0,
        total_controls: 40,
        compliant: 35,
        non_compliant: 5,
      },
      owasp: {
        score_percent: 72.0,
        total_controls: 20,
        compliant: 14,
        non_compliant: 6,
      },
    },
  } as unknown,
  isLoading: false,
  error: null as unknown,
};

/* ---- mocks ---- */

vi.mock("@/hooks/useCompliance", () => ({
  useCompliance: () => mockComplianceScore,
}));

vi.mock("@/hooks/useComplianceFramework", () => ({
  useComplianceFrameworks: () => mockFrameworksData,
  useComplianceFramework: () => mockFrameworkScore,
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

// Recharts renders SVG — mock to avoid jsdom SVG issues
vi.mock("recharts", () => ({
  PieChart: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="pie-chart">{children}</div>
  ),
  Pie: ({ children }: { children?: React.ReactNode }) => (
    <div data-testid="pie">{children}</div>
  ),
  Cell: () => <div data-testid="pie-cell" />,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <CompliancePage />
    </MemoryRouter>,
  );
}

describe("CompliancePage", () => {
  afterEach(() => {
    mockFrameworksData.data = null;
    mockFrameworksData.isLoading = false;
    mockFrameworksData.error = null;
    mockFrameworkScore.data = null;
    mockFrameworkScore.isLoading = false;
    mockFrameworkScore.error = null;
    mockComplianceScore.isLoading = false;
    mockComplianceScore.error = null;
    // Restore default data
    mockComplianceScore.data = {
      total_checks: 100,
      passed: 80,
      failed: 20,
      total_violations: 20,
      errors: 0,
      skipped: 0,
      score_percent: 80,
      by_domain: {},
      by_severity: {},
      by_framework: {
        cis_aws: {
          score_percent: 84.44,
          total_controls: 45,
          compliant: 38,
          non_compliant: 7,
        },
        nist_800_53: {
          score_percent: 76.5,
          total_controls: 60,
          compliant: 46,
          non_compliant: 14,
        },
        pci_dss: {
          score_percent: 91.0,
          total_controls: 33,
          compliant: 30,
          non_compliant: 3,
        },
        hipaa: {
          score_percent: 68.0,
          total_controls: 25,
          compliant: 17,
          non_compliant: 8,
        },
        soc2: {
          score_percent: 88.0,
          total_controls: 40,
          compliant: 35,
          non_compliant: 5,
        },
        owasp: {
          score_percent: 72.0,
          total_controls: 20,
          compliant: 14,
          non_compliant: 6,
        },
      },
    };
  });

  it("shows Compliance heading", () => {
    renderPage();
    expect(screen.getByText("Compliance")).toBeInTheDocument();
  });

  it("shows loading skeleton when data is loading", () => {
    mockComplianceScore.isLoading = true;
    mockComplianceScore.data = null;
    const { container } = renderPage();
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows error state when API fails", () => {
    mockComplianceScore.error = { message: "Network error" };
    mockComplianceScore.data = null;
    renderPage();
    expect(screen.getByText(/network error/i)).toBeInTheDocument();
  });

  it("renders 6 framework cards when data loads", () => {
    renderPage();
    expect(
      screen.getByText("CIS AWS Foundations Benchmark v1.5.0"),
    ).toBeInTheDocument();
    expect(screen.getByText("NIST 800-53")).toBeInTheDocument();
    expect(screen.getByText("PCI DSS v4.0")).toBeInTheDocument();
    expect(screen.getByText("HIPAA")).toBeInTheDocument();
    expect(screen.getByText("SOC 2")).toBeInTheDocument();
    expect(screen.getByText("OWASP Top 10")).toBeInTheDocument();
  });

  it("each card shows score percentage", () => {
    renderPage();
    // CIS AWS score
    expect(screen.getByText("84.4%")).toBeInTheDocument();
    // PCI DSS score
    expect(screen.getByText("91.0%")).toBeInTheDocument();
  });

  it("shows empty state when by_framework has no data", () => {
    mockComplianceScore.data = {
      total_checks: 0,
      passed: 0,
      failed: 0,
      total_violations: 0,
      errors: 0,
      skipped: 0,
      score_percent: 0,
      by_domain: {},
      by_severity: {},
      by_framework: {},
    };
    renderPage();
    expect(screen.getByText(/run a scan first/i)).toBeInTheDocument();
  });

  it("shows empty state when by_framework is absent", () => {
    mockComplianceScore.data = {
      total_checks: 0,
      passed: 0,
      failed: 0,
      total_violations: 0,
      errors: 0,
      skipped: 0,
      score_percent: 0,
      by_domain: {},
      by_severity: {},
    };
    renderPage();
    expect(screen.getByText(/run a scan first/i)).toBeInTheDocument();
  });

  it("clicking a framework card selects it", () => {
    renderPage();
    const card = screen.getByTestId("framework-card-cis_aws");
    fireEvent.click(card);
    // Drill-down heading should now appear
    expect(screen.getByTestId("drilldown-section")).toBeInTheDocument();
  });

  it("drill-down shows controls table on framework click", () => {
    mockFrameworkScore.data = {
      framework: "cis_aws",
      total_controls: 45,
      compliant: 38,
      non_compliant: 7,
      score_percent: 84.44,
      controls: [
        {
          control_id: "1.5",
          status: "compliant",
          check_ids: ["iam_root_mfa"],
          violations: [],
          severity: "critical",
        },
        {
          control_id: "2.1",
          status: "non_compliant",
          check_ids: ["s3_block_public_acls"],
          violations: [
            {
              resource_arn: "arn:aws:s3:::my-bucket",
              severity: "high",
              reason: "Bucket is public",
            },
          ],
          severity: "high",
        },
      ],
    };
    renderPage();
    const card = screen.getByTestId("framework-card-cis_aws");
    fireEvent.click(card);
    // Controls table columns
    expect(screen.getByText("Control ID")).toBeInTheDocument();
    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getByText("Severity")).toBeInTheDocument();
  });

  it("controls table shows control_id values", () => {
    mockFrameworkScore.data = {
      framework: "cis_aws",
      total_controls: 2,
      compliant: 1,
      non_compliant: 1,
      score_percent: 50,
      controls: [
        {
          control_id: "1.5",
          status: "compliant",
          check_ids: ["iam_root_mfa"],
          violations: [],
          severity: "critical",
        },
        {
          control_id: "2.1",
          status: "non_compliant",
          check_ids: ["s3_block_public_acls"],
          violations: [],
          severity: "high",
        },
      ],
    };
    renderPage();
    const card = screen.getByTestId("framework-card-cis_aws");
    fireEvent.click(card);
    expect(screen.getByText("1.5")).toBeInTheDocument();
    expect(screen.getByText("2.1")).toBeInTheDocument();
  });

  it("non-compliant controls show red indicator badge", () => {
    mockFrameworkScore.data = {
      framework: "cis_aws",
      total_controls: 1,
      compliant: 0,
      non_compliant: 1,
      score_percent: 0,
      controls: [
        {
          control_id: "2.1",
          status: "non_compliant",
          check_ids: ["s3_block_public_acls"],
          violations: [],
          severity: "high",
        },
      ],
    };
    renderPage();
    const card = screen.getByTestId("framework-card-cis_aws");
    fireEvent.click(card);
    const badge = screen.getByTestId("status-non_compliant-2.1");
    expect(badge).toHaveClass("text-red-600");
  });

  it("compliant controls show green indicator badge", () => {
    mockFrameworkScore.data = {
      framework: "cis_aws",
      total_controls: 1,
      compliant: 1,
      non_compliant: 0,
      score_percent: 100,
      controls: [
        {
          control_id: "1.5",
          status: "compliant",
          check_ids: ["iam_root_mfa"],
          violations: [],
          severity: "critical",
        },
      ],
    };
    renderPage();
    const card = screen.getByTestId("framework-card-cis_aws");
    fireEvent.click(card);
    const badge = screen.getByTestId("status-compliant-1.5");
    expect(badge).toHaveClass("text-green-600");
  });

  it("renders a region selector dropdown", () => {
    renderPage();
    const select = screen.getByRole("combobox", { name: /region/i });
    expect(select).toBeInTheDocument();
  });

  it("renders pie charts for each framework card", () => {
    renderPage();
    const pies = screen.getAllByTestId("pie-chart");
    expect(pies.length).toBe(6);
  });

  it("shows compliant and non_compliant counts on each card", () => {
    renderPage();
    // CIS AWS: "38 compliant" — text is split across nodes, use regex
    expect(
      screen.getAllByText(/38\s*compliant/i).length,
    ).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/7\s*failed/i).length).toBeGreaterThanOrEqual(1);
  });

  /* ---- framework version label tests ---- */

  it("renders CIS AWS with full benchmark version label", () => {
    renderPage();
    expect(
      screen.getByText("CIS AWS Foundations Benchmark v1.5.0"),
    ).toBeInTheDocument();
  });

  it("renders PCI DSS with version label", () => {
    renderPage();
    expect(screen.getByText("PCI DSS v4.0")).toBeInTheDocument();
  });

  it("does not render unversioned CIS AWS label", () => {
    renderPage();
    // The old bare "CIS AWS" text must not appear as a
    // standalone card label now that the versioned name
    // is used.
    expect(screen.queryByText("CIS AWS")).not.toBeInTheDocument();
  });

  it("does not render unversioned PCI DSS label", () => {
    renderPage();
    expect(screen.queryByText("PCI DSS")).not.toBeInTheDocument();
  });

  it("drill-down heading uses versioned CIS AWS label", () => {
    renderPage();
    const card = screen.getByTestId("framework-card-cis_aws");
    fireEvent.click(card);
    // Both the card label and the drill-down <h3> show
    // the versioned name — verify at least one is present.
    expect(
      screen.getAllByText(/CIS AWS Foundations Benchmark v1\.5\.0/).length,
    ).toBeGreaterThanOrEqual(2);
  });
});
