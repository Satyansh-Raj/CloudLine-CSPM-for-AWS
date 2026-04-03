import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import ResourceDetailPage from "../ResourceDetailPage";

const mockResource = {
  resource_id: "arn:aws:s3:::prod-bucket",
  resource_name: "prod-bucket",
  resource_type: "s3_bucket",
  technology_category: "storage",
  service: "s3",
  region: "ap-south-1",
  account_id: "832843292195",
  exposure: "internet",
  environment: "prod",
  owner: "team-data",
  tags: { env: "prod" },
  is_active: true,
  created_at: "2026-03-01T10:00:00Z",
  last_seen: "2026-03-15T10:00:00Z",
  violation_count: 3,
  critical_violations: 1,
  high_violations: 2,
  risk_score: 85,
  connected_to: [],
  managed_by: null,
  belongs_to: null,
};

const mockViolations = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useViolations: () => mockViolations,
}));

function renderPage(state?: unknown) {
  return render(
    <MemoryRouter
      initialEntries={[
        {
          pathname: "/inventory/detail",
          state: state ?? { resource: mockResource },
        },
      ]}
    >
      <Routes>
        <Route path="/inventory/detail" element={<ResourceDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ResourceDetailPage", () => {
  afterEach(() => {
    mockViolations.data = null;
    mockViolations.isLoading = false;
    mockViolations.error = null;
  });

  it("shows resource name as heading", () => {
    renderPage();
    expect(screen.getByText("prod-bucket")).toBeInTheDocument();
  });

  it("shows back link", () => {
    renderPage();
    const link = screen.getByRole("link", {
      name: /back/i,
    });
    expect(link).toHaveAttribute("href", expect.stringContaining("/inventory"));
  });

  it("shows resource metadata", () => {
    renderPage();
    expect(screen.getByText("s3_bucket")).toBeInTheDocument();
    expect(screen.getByText("s3")).toBeInTheDocument();
    expect(screen.getByText("ap-south-1")).toBeInTheDocument();
    expect(screen.getByText("832843292195")).toBeInTheDocument();
  });

  it("shows exposure status", () => {
    renderPage();
    expect(screen.getByText(/internet/i)).toBeInTheDocument();
  });

  it("shows environment", () => {
    renderPage();
    // "prod" appears in both Environment metadata
    // and tag value — verify at least one is present
    const matches = screen.getAllByText("prod");
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });

  it("shows risk score", () => {
    renderPage();
    expect(screen.getByText("85")).toBeInTheDocument();
  });

  it("shows violation summary", () => {
    // Provide live violations to match resource_id
    mockViolations.data = [
      {
        check_id: "s3_block_public_acls",
        resource: mockResource.resource_id,
        severity: "critical",
        status: "alarm",
        domain: "storage",
        reason: "Public ACLs enabled",
        compliance: {},
        remediation_id: "",
        risk_score: 90,
      },
      {
        check_id: "s3_versioning_enabled",
        resource: mockResource.resource_id,
        severity: "high",
        status: "alarm",
        domain: "storage",
        reason: "Versioning disabled",
        compliance: {},
        remediation_id: "",
        risk_score: 70,
      },
      {
        check_id: "s3_server_side_encryption",
        resource: mockResource.resource_id,
        severity: "high",
        status: "alarm",
        domain: "storage",
        reason: "Encryption disabled",
        compliance: {},
        remediation_id: "",
        risk_score: 75,
      },
    ];
    renderPage();
    // 3 total violations
    expect(screen.getByText("3")).toBeInTheDocument();
    // 1 critical
    expect(screen.getByText("1")).toBeInTheDocument();
    // 2 high
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("shows All Clear when zero violations", () => {
    const clearResource = {
      ...mockResource,
      violation_count: 0,
      critical_violations: 0,
      high_violations: 0,
      risk_score: 0,
    };
    renderPage({ resource: clearResource });
    expect(screen.getByText(/all clear/i)).toBeInTheDocument();
  });

  it("shows Last Seen date", () => {
    renderPage();
    // Should display the last_seen date
    expect(screen.getByText(/last seen/i)).toBeInTheDocument();
  });

  it("shows Days Running metric", () => {
    renderPage();
    expect(screen.getByText(/days running/i)).toBeInTheDocument();
    expect(screen.getByText(/\d+ days?/)).toBeInTheDocument();
  });

  it("shows N/A when created_at is missing", () => {
    const noCreated = { ...mockResource, created_at: null };
    renderPage({ resource: noCreated });
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("shows tags", () => {
    renderPage();
    expect(screen.getByText("env")).toBeInTheDocument();
  });

  it("shows no-data state when resource missing", () => {
    renderPage({ resource: null });
    expect(screen.getByText(/resource not found/i)).toBeInTheDocument();
  });

  it("shows violations list when data available", () => {
    mockViolations.data = [
      {
        check_id: "s3_block_public_acls",
        severity: "critical",
        status: "alarm",
        resource: "arn:aws:s3:::prod-bucket",
        reason: "Public access enabled",
        risk_score: 90,
      },
    ];
    renderPage();
    expect(screen.getByText("s3_block_public_acls")).toBeInTheDocument();
    expect(screen.getByText(/public access enabled/i)).toBeInTheDocument();
  });
});
