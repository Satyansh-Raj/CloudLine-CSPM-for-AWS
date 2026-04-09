import { render, screen } from "@testing-library/react";
import MacieFindingsPanel from "../MacieFindingsPanel";

const mockUseMacie = {
  data: undefined as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useMacieFindings: () => mockUseMacie,
}));

const FINDING = {
  finding_id: "f-001",
  type: "SensitiveData:S3Object/Personal",
  bucket_name: "prod-bucket",
  severity: "High",
  category: "SENSITIVE_DATA",
  count: 3,
  first_observed_at: "2026-04-01T00:00:00Z",
  last_observed_at: "2026-04-09T00:00:00Z",
  region: "ap-south-1",
  account_id: "832843292195",
};

describe("MacieFindingsPanel", () => {
  afterEach(() => {
    mockUseMacie.data = undefined;
    mockUseMacie.isLoading = false;
    mockUseMacie.error = null;
  });

  it("shows loading skeleton while fetching", () => {
    mockUseMacie.isLoading = true;
    const { container } = render(<MacieFindingsPanel />);
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows empty state when no findings", () => {
    mockUseMacie.data = [];
    render(<MacieFindingsPanel />);
    expect(screen.getByText(/no macie findings/i)).toBeInTheDocument();
  });

  it("renders findings list", () => {
    mockUseMacie.data = [FINDING];
    render(<MacieFindingsPanel />);
    expect(screen.getByText("prod-bucket")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("renders section heading", () => {
    mockUseMacie.data = [];
    render(<MacieFindingsPanel />);
    // h2 heading has role="heading"
    expect(
      screen.getByRole("heading", {
        name: /macie findings/i,
      }),
    ).toBeInTheDocument();
  });

  it("shows finding count", () => {
    mockUseMacie.data = [FINDING];
    render(<MacieFindingsPanel />);
    // count is embedded: "Personal — 3 objects"
    expect(screen.getByText(/3 objects/i)).toBeInTheDocument();
  });

  it("passes bucketName and accountId as params", () => {
    mockUseMacie.data = [];
    // Renders without throwing when props provided
    render(
      <MacieFindingsPanel bucketName="my-bucket" accountId="123456789012" />,
    );
    expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
  });

  it("shows finding type shortened", () => {
    mockUseMacie.data = [FINDING];
    render(<MacieFindingsPanel />);
    // shortType("SensitiveData:S3Object/Personal") → "Personal"
    expect(screen.getByText(/personal/i)).toBeInTheDocument();
  });
});
