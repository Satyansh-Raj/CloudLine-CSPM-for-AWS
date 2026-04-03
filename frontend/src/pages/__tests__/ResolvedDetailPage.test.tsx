import { render, screen, fireEvent } from "@testing-library/react";
import ResolvedDetailPage from "../ResolvedDetailPage";

const mockNavigate = vi.fn();

const mockViolation = {
  check_id: "iam_root_mfa",
  resource: "arn:aws:iam::832843292195:root",
  severity: "critical" as const,
  status: "ok" as const,
  domain: "identity",
  reason: "MFA enabled",
  remediation_id: "iam_root_mfa",
  compliance: {
    cis_aws: ["1.5"],
    nist_800_53: ["IA-2(1)"],
    pci_dss: ["8.3.1"],
    hipaa: [],
    soc2: [],
  },
  risk_score: 0,
  first_detected: "2026-02-01T08:00:00Z",
  resolved_at: "2026-03-15T09:00:00Z",
  last_evaluated: "2026-03-15T09:00:00Z",
  previous_status: "alarm",
  status_history: [
    {
      status: "alarm",
      timestamp: "2026-02-01T08:00:00Z",
    },
    {
      status: "ok",
      timestamp: "2026-03-15T09:00:00Z",
    },
  ],
  regression_count: 0,
};

const mockLocation = {
  state: { violation: mockViolation } as {
    violation: typeof mockViolation | null;
  } | null,
};

const mockViolationsData = {
  data: [] as (typeof mockViolation)[],
  isLoading: false,
  error: null as unknown,
};

// Mock recharts
vi.mock("recharts", () => ({
  AreaChart: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="area-chart">{children}</div>
  ),
  Area: () => <div data-testid="area" />,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
  ReferenceLine: () => null,
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({
      checkId: "iam_root_mfa",
      resource: encodeURIComponent("arn:aws:iam::832843292195:root"),
    }),
    useLocation: () => mockLocation,
  };
});

vi.mock("@/hooks", () => ({
  useViolations: () => mockViolationsData,
}));

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "832843292195",
    accounts: [],
    isLoading: false,
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => ({
    selectedRegion: "ap-south-1",
    regions: ["ap-south-1"],
    isLoading: false,
    setSelectedRegion: vi.fn(),
  }),
}));

function renderPage() {
  const { MemoryRouter } = require("react-router-dom");
  return render(
    <MemoryRouter>
      <ResolvedDetailPage />
    </MemoryRouter>,
  );
}

describe("ResolvedDetailPage", () => {
  afterEach(() => {
    mockLocation.state = { violation: mockViolation };
    mockViolationsData.data = [];
    mockViolationsData.isLoading = false;
    mockViolationsData.error = null;
    mockNavigate.mockClear();
  });

  /* ---- header ---- */

  it("renders back button", () => {
    renderPage();
    expect(screen.getByText("Back")).toBeInTheDocument();
  });

  it("navigates back on back button click", () => {
    renderPage();
    fireEvent.click(screen.getByText("Back"));
    expect(mockNavigate).toHaveBeenCalledWith(-1);
  });

  it("shows resolved status badge", () => {
    renderPage();
    expect(screen.getByText("Resolved")).toBeInTheDocument();
  });

  it("shows human-readable check name", () => {
    renderPage();
    expect(
      screen.getByText("Root Account MFA Not Enabled"),
    ).toBeInTheDocument();
  });

  it("shows severity badge", () => {
    renderPage();
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("shows check_id in header", () => {
    renderPage();
    expect(screen.getByText("iam_root_mfa")).toBeInTheDocument();
  });

  it("shows domain name", () => {
    renderPage();
    expect(screen.getByText("identity")).toBeInTheDocument();
  });

  /* ---- details section ---- */

  it("shows resource ARN", () => {
    renderPage();
    expect(
      screen.getByText("arn:aws:iam::832843292195:root"),
    ).toBeInTheDocument();
  });

  it("shows reason text", () => {
    renderPage();
    expect(screen.getByText("MFA enabled")).toBeInTheDocument();
  });

  /* ---- timestamps ---- */

  it("shows First Detected label", () => {
    renderPage();
    expect(screen.getByText("First Detected")).toBeInTheDocument();
  });

  it("shows Resolved At label", () => {
    renderPage();
    expect(screen.getByText("Resolved At")).toBeInTheDocument();
  });

  it("shows Last Evaluated label", () => {
    renderPage();
    expect(screen.getByText("Last Evaluated")).toBeInTheDocument();
  });

  /* ---- risk score ---- */

  it("shows risk score section", () => {
    renderPage();
    expect(screen.getByText("Risk Score")).toBeInTheDocument();
  });

  it("shows score value", () => {
    renderPage();
    expect(screen.getByText("/ 100")).toBeInTheDocument();
  });

  /* ---- compliance ---- */

  it("shows compliance section heading", () => {
    renderPage();
    expect(screen.getByText("Compliance")).toBeInTheDocument();
  });

  it("shows CIS AWS controls", () => {
    renderPage();
    expect(
      screen.getByText("CIS AWS Foundations Benchmark v1.5.0"),
    ).toBeInTheDocument();
    expect(screen.getByText("1.5")).toBeInTheDocument();
  });

  it("shows NIST controls", () => {
    renderPage();
    expect(screen.getByText("NIST 800-53")).toBeInTheDocument();
    expect(screen.getByText("IA-2(1)")).toBeInTheDocument();
  });

  /* ---- issue history chart ---- */

  it("renders issue history chart", () => {
    renderPage();
    expect(screen.getByTestId("issue-history-chart")).toBeInTheDocument();
  });

  it("shows Issue History heading", () => {
    renderPage();
    expect(screen.getByText("Issue History")).toBeInTheDocument();
  });

  /* ---- regression count ---- */

  it("shows regression count", () => {
    renderPage();
    expect(screen.getByText("Regressions")).toBeInTheDocument();
  });

  /* ---- not found state ---- */

  it("shows not-found when no violation", () => {
    mockLocation.state = null;
    mockViolationsData.data = [];
    renderPage();
    expect(screen.getByText("Violation not found")).toBeInTheDocument();
  });

  /* ---- cache fallback ---- */

  it("finds violation from cache", () => {
    mockLocation.state = null;
    mockViolationsData.data = [mockViolation];
    renderPage();
    expect(
      screen.getByText("Root Account MFA Not Enabled"),
    ).toBeInTheDocument();
  });
});
