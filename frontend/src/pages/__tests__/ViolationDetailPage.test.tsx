import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ViolationDetailPage from "../ViolationDetailPage";

const mockNavigate = vi.fn();

const mockViolation = {
  check_id: "s3_01",
  resource: "arn:aws:s3:::bucket-1",
  severity: "critical" as const,
  status: "alarm" as const,
  domain: "data_protection",
  reason: "S3 bucket has public access enabled",
  remediation_id: "REM_s3_01",
  compliance: {
    cis_aws: ["2.1.4"],
    nist_800_53: ["AC-3"],
    pci_dss: [],
    hipaa: [],
    soc2: [],
  },
  risk_score: 85,
};

// Mutable — tests can override between cases
const mockLocation = {
  state: { violation: mockViolation } as {
    violation: typeof mockViolation | null;
  } | null,
};
const mockViolationsData = {
  data: [] as typeof mockViolation[],
  isLoading: false,
  error: null as unknown,
};

vi.mock("react-router-dom", async () => {
  const actual =
    await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({
      checkId: "s3_01",
      resource: encodeURIComponent(
        "arn:aws:s3:::bucket-1",
      ),
    }),
    useLocation: () => mockLocation,
  };
});

vi.mock("@/hooks", () => ({
  useViolations: () => mockViolationsData,
}));

vi.mock(
  "@/components/violations/RemediationTabs",
  () => ({
    default: () => (
      <div data-testid="remediation-tabs" />
    ),
  }),
);

function renderPage() {
  return render(<ViolationDetailPage />);
}

describe("ViolationDetailPage — violation present", () => {
  beforeEach(() => {
    mockNavigate.mockClear();
    mockLocation.state = { violation: mockViolation };
    mockViolationsData.data = [];
  });

  it("renders back button", () => {
    renderPage();
    expect(
      screen.getByText("Back"),
    ).toBeInTheDocument();
  });

  it("navigates to /violations on back click", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      screen.getByText("Back"),
    );
    expect(mockNavigate).toHaveBeenCalledWith(-1);
  });

  it("shows human-readable check name", () => {
    renderPage();
    expect(
      screen.getByText("S3 BlockPublicAcls Not Enabled"),
    ).toBeInTheDocument();
  });

  it("shows check_id badge", () => {
    renderPage();
    expect(
      screen.getByText("s3_01"),
    ).toBeInTheDocument();
  });

  it("shows resource ARN", () => {
    renderPage();
    expect(
      screen.getByText("arn:aws:s3:::bucket-1"),
    ).toBeInTheDocument();
  });

  it("shows reason text", () => {
    renderPage();
    expect(
      screen.getByText(
        "S3 bucket has public access enabled",
      ),
    ).toBeInTheDocument();
  });

  it("shows risk score", () => {
    renderPage();
    expect(screen.getByText("85")).toBeInTheDocument();
  });

  it("renders How to Fix section with tabs", () => {
    renderPage();
    expect(
      screen.getByText("How to Fix"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("remediation-tabs"),
    ).toBeInTheDocument();
  });

  it("shows compliance controls", () => {
    renderPage();
    expect(
      screen.getByText("2.1.4"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("AC-3"),
    ).toBeInTheDocument();
  });
});

describe("ViolationDetailPage — not found", () => {
  beforeEach(() => {
    mockLocation.state = null;
    mockViolationsData.data = [];
  });

  it("shows not found message", () => {
    renderPage();
    expect(
      screen.getByText("Violation not found"),
    ).toBeInTheDocument();
  });

  it("still renders back button", () => {
    renderPage();
    expect(
      screen.getByText("Back"),
    ).toBeInTheDocument();
  });
});

describe("ViolationDetailPage — cache fallback", () => {
  beforeEach(() => {
    mockLocation.state = null;
    mockViolationsData.data = [mockViolation];
  });

  it("finds violation from violations cache", () => {
    renderPage();
    expect(
      screen.getByText("S3 BlockPublicAcls Not Enabled"),
    ).toBeInTheDocument();
  });
});
