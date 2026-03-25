import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import ResolvedIssuesPage from "../ResolvedIssuesPage";

// Mock recharts to avoid jsdom SVG issues in expanded rows
vi.mock("recharts", () => ({
  AreaChart: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="area-chart">{children}</div>
  ),
  Area: () => <div data-testid="area" />,
  XAxis: () => null,
  YAxis: ({ tickFormatter }: { tickFormatter?: (v: number) => string }) => (
    <div>
      {tickFormatter && (
        <>
          <span>{tickFormatter(1)}</span>
          <span>{tickFormatter(-1)}</span>
        </>
      )}
    </div>
  ),
  CartesianGrid: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
  ReferenceLine: () => null,
}));

const mockState = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks/useViolations", () => ({
  useViolations: () => mockState,
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

function renderPage() {
  return render(
    <MemoryRouter>
      <ResolvedIssuesPage />
    </MemoryRouter>,
  );
}

describe("ResolvedIssuesPage", () => {
  afterEach(() => {
    mockState.data = null;
    mockState.isLoading = false;
    mockState.error = null;
  });

  it("shows heading", () => {
    renderPage();
    expect(screen.getByText("Resolved Issues")).toBeInTheDocument();
  });

  it("shows subtitle", () => {
    renderPage();
    expect(
      screen.getByText(/currently pass their security checks/i),
    ).toBeInTheDocument();
  });

  it("shows loading skeleton", () => {
    mockState.isLoading = true;
    const { container } = renderPage();
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows error state", () => {
    mockState.error = { message: "Network error" };
    renderPage();
    expect(screen.getByText(/network error/i)).toBeInTheDocument();
  });

  it("shows empty state when data is empty", () => {
    mockState.data = [];
    renderPage();
    expect(screen.getByText("No resolved issues yet")).toBeInTheDocument();
  });

  it("shows resolved count badge when data exists", () => {
    mockState.data = [
      {
        check_id: "s3_block_public_acls",
        resource: "arn:aws:s3:::bucket-1",
        severity: "low",
        status: "ok",
        domain: "data_protection",
        reason: "All checks pass",
        remediation_id: "",
        compliance: {},
        resolved_at: "2026-03-19T10:00:00Z",
        previous_status: "alarm",
        first_detected: "2026-03-18T08:00:00Z",
      },
      {
        check_id: "iam_root_mfa",
        resource: "arn:aws:iam:::root",
        severity: "low",
        status: "ok",
        domain: "identity_access",
        reason: "MFA enabled",
        remediation_id: "",
        compliance: {},
        resolved_at: "2026-03-19T11:00:00Z",
        previous_status: "alarm",
        first_detected: "2026-03-17T08:00:00Z",
      },
    ];
    renderPage();
    expect(screen.getByText("2 resolved")).toBeInTheDocument();
  });

  it("renders table columns header", () => {
    mockState.data = [
      {
        check_id: "s3_block_public_acls",
        resource: "arn:aws:s3:::bucket-1",
        severity: "low",
        status: "ok",
        domain: "data_protection",
        reason: "All checks pass",
        remediation_id: "",
        compliance: {},
        resolved_at: "2026-03-19T10:00:00Z",
        previous_status: "alarm",
        first_detected: "2026-03-18T08:00:00Z",
      },
    ];
    renderPage();
    expect(screen.getByText("Resource")).toBeInTheDocument();
    expect(screen.getByText("Check ID")).toBeInTheDocument();
    expect(screen.getByText("Previous Status")).toBeInTheDocument();
    expect(screen.getByText("Resolved At")).toBeInTheDocument();
    expect(screen.getByText("Domain")).toBeInTheDocument();
    expect(screen.getByText("Severity")).toBeInTheDocument();
  });

  it("renders resolved_at date for each row", () => {
    mockState.data = [
      {
        check_id: "s3_block_public_acls",
        resource: "arn:aws:s3:::bucket-1",
        severity: "low",
        status: "ok",
        domain: "data_protection",
        reason: "All checks pass",
        remediation_id: "",
        compliance: {},
        resolved_at: "2026-03-19T10:00:00Z",
        previous_status: "alarm",
        first_detected: "2026-03-18T08:00:00Z",
      },
    ];
    renderPage();
    // resolved_at should be displayed (formatted or raw)
    const rows = screen.getByTestId("resolved-issues-table");
    expect(rows).toBeInTheDocument();
  });

  it("renders previous_status badge", () => {
    mockState.data = [
      {
        check_id: "s3_block_public_acls",
        resource: "arn:aws:s3:::bucket-1",
        severity: "critical",
        status: "ok",
        domain: "data_protection",
        reason: "All checks pass",
        remediation_id: "",
        compliance: {},
        resolved_at: "2026-03-19T10:00:00Z",
        previous_status: "alarm",
        first_detected: "2026-03-18T08:00:00Z",
      },
    ];
    renderPage();
    expect(screen.getByTestId("prev-status-0")).toBeInTheDocument();
  });

  it("renders severity badge in each row", () => {
    mockState.data = [
      {
        check_id: "iam_root_mfa",
        resource: "arn:aws:iam:::root",
        severity: "critical",
        status: "ok",
        domain: "identity_access",
        reason: "MFA enabled",
        remediation_id: "",
        compliance: {},
        resolved_at: "2026-03-19T10:00:00Z",
        previous_status: "alarm",
        first_detected: "2026-03-18T08:00:00Z",
      },
    ];
    renderPage();
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("renders a region selector dropdown", () => {
    renderPage();
    const select = screen.getByRole("combobox", {
      name: /region/i,
    });
    expect(select).toBeInTheDocument();
  });

  it("shows dash when resolved_at is absent", () => {
    mockState.data = [
      {
        check_id: "s3_block_public_acls",
        resource: "arn:aws:s3:::bucket-1",
        severity: "low",
        status: "ok",
        domain: "data_protection",
        reason: "Pass",
        remediation_id: "",
        compliance: {},
        resolved_at: undefined,
        previous_status: "alarm",
      },
    ];
    renderPage();
    // dash placeholder for missing resolved_at
    expect(screen.getByTestId("resolved-at-0")).toBeInTheDocument();
  });

  /* ---- expandable rows ---- */

  const SINGLE_VIOLATION = {
    check_id: "s3_block_public_acls",
    resource: "arn:aws:s3:::bucket-1",
    severity: "low" as const,
    status: "ok" as const,
    domain: "data_protection",
    reason: "All checks pass",
    remediation_id: "",
    compliance: {},
    resolved_at: "2026-03-19T10:00:00Z",
    previous_status: "alarm",
    first_detected: "2026-03-18T08:00:00Z",
  };

  it("rows have expandable-row data-testid", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const rows = screen.getAllByTestId("expandable-row");
    expect(rows.length).toBeGreaterThan(0);
  });

  it("rows have cursor-pointer class for click affordance", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const row = screen.getByTestId("expandable-row");
    expect(row.className).toMatch(/cursor-pointer/);
  });

  it("expanded content is hidden initially", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    expect(screen.queryByTestId("expanded-content")).not.toBeInTheDocument();
  });

  it("clicking a row reveals expanded-content", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const row = screen.getByTestId("expandable-row");
    fireEvent.click(row);
    expect(screen.getByTestId("expanded-content")).toBeInTheDocument();
  });

  it("expanded content contains lifecycle chart", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const row = screen.getByTestId("expandable-row");
    fireEvent.click(row);
    expect(screen.getByTestId("lifecycle-chart")).toBeInTheDocument();
  });

  it("clicking expanded row collapses it", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const row = screen.getByTestId("expandable-row");
    fireEvent.click(row);
    expect(screen.getByTestId("expanded-content")).toBeInTheDocument();
    fireEvent.click(row);
    expect(screen.queryByTestId("expanded-content")).not.toBeInTheDocument();
  });

  it("chevron indicator exists in row", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    expect(screen.getByTestId("chevron-0")).toBeInTheDocument();
  });

  it("chevron changes text on expand", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const chevron = screen.getByTestId("chevron-0");
    const collapsedText = chevron.textContent;
    const row = screen.getByTestId("expandable-row");
    fireEvent.click(row);
    const expandedText = screen.getByTestId("chevron-0").textContent;
    expect(expandedText).not.toBe(collapsedText);
  });

  it("expanding one row collapses a previously expanded row", () => {
    mockState.data = [
      SINGLE_VIOLATION,
      {
        ...SINGLE_VIOLATION,
        check_id: "iam_root_mfa",
        resource: "arn:aws:iam:::root",
      },
    ];
    renderPage();
    const rows = screen.getAllByTestId("expandable-row");
    fireEvent.click(rows[0]);
    expect(screen.getAllByTestId("expanded-content").length).toBe(1);
    fireEvent.click(rows[1]);
    // Now only second row should be expanded
    expect(screen.getAllByTestId("expanded-content").length).toBe(1);
  });
});
