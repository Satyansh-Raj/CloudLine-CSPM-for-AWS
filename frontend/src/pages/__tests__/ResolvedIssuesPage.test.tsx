import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import ResolvedIssuesPage from "../ResolvedIssuesPage";

const mockState = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useViolations: () => mockState,
}));

vi.mock("@/components/violations", () => ({
  ViolationsTable: ({
    data,
  }: {
    data: unknown[];
  }) => (
    <div data-testid="table">{data.length} rows</div>
  ),
  ViolationFilters: () => (
    <div data-testid="filters" />
  ),
  RemediationTabs: () => (
    <div data-testid="remediation-tabs" />
  ),
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
    expect(
      screen.getByText("Resolved Issues"),
    ).toBeInTheDocument();
  });

  it("shows subtitle", () => {
    renderPage();
    expect(
      screen.getByText(
        /currently pass their security checks/i,
      ),
    ).toBeInTheDocument();
  });

  it("shows loading skeleton", () => {
    mockState.isLoading = true;
    const { container } = renderPage();
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error state", () => {
    mockState.error = { message: "Network error" };
    renderPage();
    expect(
      screen.getByText(/network error/i),
    ).toBeInTheDocument();
  });

  it("shows empty state when data is empty", () => {
    mockState.data = [];
    renderPage();
    expect(
      screen.getByText("No resolved issues yet"),
    ).toBeInTheDocument();
  });

  it("shows table when data exists", () => {
    mockState.data = [
      {
        check_id: "s3_01",
        resource: "arn:aws:s3:::bucket-1",
        severity: "low",
        status: "ok",
        domain: "data_protection",
        reason: "All checks pass",
        remediation_id: "",
        compliance: {},
      },
    ];
    renderPage();
    expect(
      screen.getByTestId("table"),
    ).toBeInTheDocument();
  });

  it("shows resolved count badge when data exists", () => {
    mockState.data = [
      {
        check_id: "s3_01",
        resource: "arn:aws:s3:::bucket-1",
        severity: "low",
        status: "ok",
        domain: "data_protection",
        reason: "All checks pass",
        remediation_id: "",
        compliance: {},
      },
      {
        check_id: "iam_01",
        resource: "arn:aws:iam:::root",
        severity: "low",
        status: "ok",
        domain: "identity",
        reason: "MFA enabled",
        remediation_id: "",
        compliance: {},
      },
    ];
    renderPage();
    expect(
      screen.getByText("2 resolved"),
    ).toBeInTheDocument();
  });
});
