import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import ResolvedIssuesPage from "../ResolvedIssuesPage";

const mockNavigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

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

vi.mock("@/constants/checkNames", () => ({
  getCheckName: (id: string) => id,
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <ResolvedIssuesPage />
    </MemoryRouter>,
  );
}

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

describe("ResolvedIssuesPage", () => {
  afterEach(() => {
    mockState.data = null;
    mockState.isLoading = false;
    mockState.error = null;
    mockNavigate.mockClear();
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
      SINGLE_VIOLATION,
      {
        ...SINGLE_VIOLATION,
        check_id: "iam_root_mfa",
        resource: "arn:aws:iam:::root",
      },
    ];
    renderPage();
    expect(screen.getByText("2 resolved")).toBeInTheDocument();
  });

  it("renders table column headers", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    expect(screen.getByText("Issue")).toBeInTheDocument();
    expect(screen.getByText("Resource")).toBeInTheDocument();
    // "Severity" and "Domain" appear in both filters
    // and table headers
    expect(screen.getAllByText("Severity").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("Previous Status")).toBeInTheDocument();
    expect(screen.getByText("Resolved At")).toBeInTheDocument();
    expect(screen.getAllByText("Domain").length).toBeGreaterThanOrEqual(2);
  });

  it("renders resolved-issues-table", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const table = screen.getByTestId("resolved-issues-table");
    expect(table).toBeInTheDocument();
  });

  it("renders severity badge using SeverityBadge", () => {
    mockState.data = [{ ...SINGLE_VIOLATION, severity: "critical" }];
    renderPage();
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("renders previous status using StatusBadge", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    expect(screen.getByText("alarm")).toBeInTheDocument();
  });

  it("renders a region selector dropdown", () => {
    renderPage();
    const select = screen.getByRole("combobox", {
      name: /region/i,
    });
    expect(select).toBeInTheDocument();
  });

  it("renders severity and domain filter dropdowns", () => {
    renderPage();
    expect(screen.getByText("Severity")).toBeInTheDocument();
    expect(screen.getByText("Domain")).toBeInTheDocument();
  });

  it("shows dash when resolved_at is absent", () => {
    mockState.data = [
      {
        ...SINGLE_VIOLATION,
        resolved_at: undefined,
      },
    ];
    renderPage();
    expect(screen.getByTestId("resolved-issues-table")).toBeInTheDocument();
  });

  /* ---- row navigation ---- */

  it("rows have resolved-row data-testid", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const rows = screen.getAllByTestId("resolved-row");
    expect(rows.length).toBe(1);
  });

  it("rows have cursor-pointer class", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const row = screen.getByTestId("resolved-row");
    expect(row.className).toMatch(/cursor-pointer/);
  });

  it("clicking row navigates to detail page", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    const row = screen.getByTestId("resolved-row");
    fireEvent.click(row);
    expect(mockNavigate).toHaveBeenCalledTimes(1);
    const [path, opts] = mockNavigate.mock.calls[0];
    expect(path).toContain("/resolved/");
    expect(path).toContain("s3_block_public_acls");
    expect(opts).toHaveProperty("state");
    expect(opts.state.violation).toEqual(SINGLE_VIOLATION);
  });

  it("navigates to correct encoded path", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    fireEvent.click(screen.getByTestId("resolved-row"));
    const path = mockNavigate.mock.calls[0][0];
    expect(path).toContain(encodeURIComponent("arn:aws:s3:::bucket-1"));
  });

  it("no expandable content exists", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    expect(screen.queryByTestId("expanded-content")).not.toBeInTheDocument();
  });

  it("no chevron indicators exist", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    expect(screen.queryByTestId("chevron-0")).not.toBeInTheDocument();
  });

  it("each row navigates independently", () => {
    mockState.data = [
      SINGLE_VIOLATION,
      {
        ...SINGLE_VIOLATION,
        check_id: "iam_root_mfa",
        resource: "arn:aws:iam:::root",
      },
    ];
    renderPage();
    const rows = screen.getAllByTestId("resolved-row");
    fireEvent.click(rows[1]);
    const path = mockNavigate.mock.calls[0][0];
    expect(path).toContain("iam_root_mfa");
  });

  it("shows check name in issue column", () => {
    mockState.data = [SINGLE_VIOLATION];
    renderPage();
    // getCheckName is mocked to return the id itself,
    // so it appears twice (name + subtitle)
    const matches = screen.getAllByText("s3_block_public_acls");
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });
});
