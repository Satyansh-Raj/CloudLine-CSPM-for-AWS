import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ViolationDetailPage from "../ViolationDetailPage";

const mockNavigate = vi.fn();

const mockViolation = {
  check_id: "s3_block_public_acls",
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

// Violation with an existing Jira ticket
const mockViolationWithTicket = {
  ...mockViolation,
  ticket_id: "10042",
  ticket_url: "https://example.atlassian.net/browse/SEC-42",
};

// Mutable — tests can override between cases
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

// Mutable mutation state — tests override per case
const mockMutationState = {
  mutate: vi.fn(),
  isPending: false,
  isSuccess: false,
  isError: false,
  error: null as Error | null,
  data: undefined as
    | {
        ticket_id: string;
        ticket_url: string;
        ticket_key: string;
      }
    | undefined,
};

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({
      checkId: "s3_block_public_acls",
      resource: encodeURIComponent("arn:aws:s3:::bucket-1"),
    }),
    useLocation: () => mockLocation,
  };
});

vi.mock("@/hooks", () => ({
  useViolations: () => mockViolationsData,
  useCreateJiraTicket: () => mockMutationState,
}));

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "123456789012",
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

vi.mock("@/components/violations/RemediationTabs", () => ({
  default: () => <div data-testid="remediation-tabs" />,
}));

function renderPage() {
  return render(<ViolationDetailPage />);
}

describe("ViolationDetailPage — violation present", () => {
  beforeEach(() => {
    mockNavigate.mockClear();
    mockMutationState.mutate = vi.fn();
    mockMutationState.isPending = false;
    mockMutationState.isSuccess = false;
    mockMutationState.isError = false;
    mockMutationState.error = null;
    mockMutationState.data = undefined;
    mockLocation.state = { violation: mockViolation };
    mockViolationsData.data = [];
  });

  it("renders back button", () => {
    renderPage();
    expect(screen.getByText("Back")).toBeInTheDocument();
  });

  it("navigates to /violations on back click", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByText("Back"));
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
    expect(screen.getByText("s3_block_public_acls")).toBeInTheDocument();
  });

  it("shows resource ARN", () => {
    renderPage();
    expect(screen.getByText("arn:aws:s3:::bucket-1")).toBeInTheDocument();
  });

  it("shows reason text", () => {
    renderPage();
    expect(
      screen.getByText("S3 bucket has public access enabled"),
    ).toBeInTheDocument();
  });

  it("shows risk score", () => {
    renderPage();
    expect(screen.getByText("85")).toBeInTheDocument();
  });

  it("renders How to Fix section with tabs", () => {
    renderPage();
    expect(screen.getByText("How to Fix")).toBeInTheDocument();
    expect(screen.getByTestId("remediation-tabs")).toBeInTheDocument();
  });

  it("shows compliance controls", () => {
    renderPage();
    expect(screen.getByText("2.1.4")).toBeInTheDocument();
    expect(screen.getByText("AC-3")).toBeInTheDocument();
  });
});

describe("ViolationDetailPage — not found", () => {
  beforeEach(() => {
    mockMutationState.mutate = vi.fn();
    mockMutationState.isPending = false;
    mockMutationState.isSuccess = false;
    mockMutationState.isError = false;
    mockMutationState.error = null;
    mockMutationState.data = undefined;
    mockLocation.state = null;
    mockViolationsData.data = [];
  });

  it("shows not found message", () => {
    renderPage();
    expect(screen.getByText("Violation not found")).toBeInTheDocument();
  });

  it("still renders back button", () => {
    renderPage();
    expect(screen.getByText("Back")).toBeInTheDocument();
  });
});

describe("ViolationDetailPage — cache fallback", () => {
  beforeEach(() => {
    mockMutationState.mutate = vi.fn();
    mockMutationState.isPending = false;
    mockMutationState.isSuccess = false;
    mockMutationState.isError = false;
    mockMutationState.error = null;
    mockMutationState.data = undefined;
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

describe("ViolationDetailPage — Jira ticket (no ticket)", () => {
  beforeEach(() => {
    mockMutationState.mutate = vi.fn();
    mockMutationState.isPending = false;
    mockMutationState.isSuccess = false;
    mockMutationState.isError = false;
    mockMutationState.error = null;
    mockMutationState.data = undefined;
    mockLocation.state = { violation: mockViolation };
    mockViolationsData.data = [];
  });

  it("renders Create Jira Ticket button when no ticket_id", () => {
    renderPage();
    expect(screen.getByTestId("create-ticket-btn")).toBeInTheDocument();
    expect(screen.getByTestId("create-ticket-btn")).toHaveTextContent(
      "Create Jira Ticket",
    );
  });

  it("does NOT render ticket link when no ticket_id", () => {
    renderPage();
    expect(screen.queryByTestId("ticket-link")).not.toBeInTheDocument();
  });

  it("calls mutate with correct params on button click", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId("create-ticket-btn"));
    expect(mockMutationState.mutate).toHaveBeenCalledWith(
      expect.objectContaining({
        check_id: "s3_block_public_acls",
        resource_id: "arn:aws:s3:::bucket-1",
      }),
    );
  });

  it("shows spinner and disables button while pending", () => {
    mockMutationState.isPending = true;
    renderPage();
    const btn = screen.getByTestId("create-ticket-btn");
    expect(btn).toBeDisabled();
    expect(screen.getByTestId("ticket-loading")).toBeInTheDocument();
  });

  it("shows error banner when mutation fails", () => {
    mockMutationState.isError = true;
    mockMutationState.error = new Error("Jira not configured");
    renderPage();
    expect(screen.getByTestId("ticket-error")).toBeInTheDocument();
    expect(screen.getByTestId("ticket-error")).toHaveTextContent(
      "Jira not configured",
    );
  });
});

describe("ViolationDetailPage — Jira ticket (has ticket)", () => {
  beforeEach(() => {
    mockMutationState.mutate = vi.fn();
    mockMutationState.isPending = false;
    mockMutationState.isSuccess = false;
    mockMutationState.isError = false;
    mockMutationState.error = null;
    mockMutationState.data = undefined;
    mockLocation.state = {
      violation: mockViolationWithTicket,
    };
    mockViolationsData.data = [];
  });

  it("does NOT render Create Jira Ticket button when ticket exists", () => {
    renderPage();
    expect(screen.queryByTestId("create-ticket-btn")).not.toBeInTheDocument();
  });

  it("renders ticket link with correct href", () => {
    renderPage();
    const link = screen.getByTestId("ticket-link");
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute(
      "href",
      "https://example.atlassian.net/browse/SEC-42",
    );
  });

  it("ticket link opens in a new tab", () => {
    renderPage();
    const link = screen.getByTestId("ticket-link");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("ticket link is not displayed when ticket_id is present but ticket_url is missing", () => {
    mockLocation.state = {
      violation: {
        ...mockViolation,
        ticket_id: "10042",
        ticket_url: undefined,
      },
    };
    renderPage();
    // No ticket_url means no link to render
    expect(screen.queryByTestId("ticket-link")).not.toBeInTheDocument();
    // Button should also not appear (ticket_id exists)
    expect(screen.queryByTestId("create-ticket-btn")).not.toBeInTheDocument();
  });
});
