import {
  render,
  screen,
  fireEvent,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import PoliciesPage from "../PoliciesPage";

/* ── Mock API module ──────────────────────────── */
const mockPolicies = [
  {
    check_id: "iam_01",
    filename: "iam.rego",
    package_name: "aws.identity.iam",
    domain: "identity",
    service: "iam",
    severity: "critical",
    path: "identity/iam.rego",
    rule_count: 2,
    description: "User has no MFA",
  },
  {
    check_id: "s3_01",
    filename: "s3.rego",
    package_name: "aws.data_protection.s3",
    domain: "data_protection",
    service: "s3",
    severity: "high",
    path: "data_protection/s3.rego",
    rule_count: 1,
    description: "Bucket is public",
  },
  {
    check_id: "vpc_01",
    filename: "vpc.rego",
    package_name: "aws.network.vpc",
    domain: "network",
    service: "vpc",
    severity: "medium",
    path: "network/vpc.rego",
    rule_count: 3,
    description: "Flow logs disabled",
  },
];

const mockGetPolicies = vi.fn();
const mockCreatePolicy = vi.fn();
const mockCreateRawPolicy = vi.fn();
const mockDeletePolicy = vi.fn();
const mockGetPolicySource = vi.fn();

vi.mock("@/api/policies", () => ({
  getPolicies: (...args: unknown[]) =>
    mockGetPolicies(...args),
  createPolicy: (...args: unknown[]) =>
    mockCreatePolicy(...args),
  createRawPolicy: (...args: unknown[]) =>
    mockCreateRawPolicy(...args),
  deletePolicy: (...args: unknown[]) =>
    mockDeletePolicy(...args),
  getPolicySource: (...args: unknown[]) =>
    mockGetPolicySource(...args),
}));

vi.mock("@/constants/checkNames", () => ({
  getCheckName: (id: string) =>
    `Name for ${id}`,
}));

vi.mock("@/components/shared/SeverityBadge", () => ({
  default: ({ severity }: { severity: string }) => (
    <span data-testid="severity">{severity}</span>
  ),
}));

function createWrapper() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      {children}
    </QueryClientProvider>
  );
}

function renderPage() {
  return render(<PoliciesPage />, {
    wrapper: createWrapper(),
  });
}

/* ── Tests ────────────────────────────────────── */

describe("PoliciesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetPolicies.mockResolvedValue(
      mockPolicies,
    );
  });

  it("renders page heading", async () => {
    renderPage();
    expect(
      screen.getByText("Rego Policies"),
    ).toBeInTheDocument();
  });

  it("renders policy list grouped by domain", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("Identity & Access"),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText("Data Protection"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Network"),
    ).toBeInTheDocument();
  });

  it("shows check ids and names", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("iam_01"),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText("Name for iam_01"),
    ).toBeInTheDocument();
  });

  it("shows severity badges", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getAllByTestId("severity").length,
      ).toBeGreaterThanOrEqual(3);
    });
  });

  it("shows rule count badges", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("2 rules"),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText("1 rule"),
    ).toBeInTheDocument();
  });

  it("filters policies by search query", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("iam_01"),
      ).toBeInTheDocument();
    });
    const searchInput =
      screen.getByPlaceholderText("Search rules...");
    fireEvent.change(searchInput, {
      target: { value: "vpc" },
    });
    expect(
      screen.queryByText("iam_01"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("vpc_01"),
    ).toBeInTheDocument();
  });

  it("shows no-match message when filter has no results", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("iam_01"),
      ).toBeInTheDocument();
    });
    const searchInput =
      screen.getByPlaceholderText("Search rules...");
    fireEvent.change(searchInput, {
      target: { value: "nonexistent_xyz" },
    });
    expect(
      screen.getByText(
        "No policies match your search.",
      ),
    ).toBeInTheDocument();
  });

  it("collapses domain groups on click", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("iam_01"),
      ).toBeInTheDocument();
    });
    // The domain header is a button, not an option
    const identityHeaders = screen.getAllByText(
      "Identity & Access",
    );
    // Find the one that is a span inside a button
    const headerSpan = identityHeaders.find(
      (el) => el.tagName === "SPAN" &&
        el.closest("button"),
    )!;
    fireEvent.click(headerSpan);
    expect(
      screen.queryByText("iam_01"),
    ).not.toBeInTheDocument();
    // Expand again
    fireEvent.click(headerSpan);
    expect(
      screen.getByText("iam_01"),
    ).toBeInTheDocument();
  });

  it("shows total count badge", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("3"),
      ).toBeInTheDocument();
    });
  });
});

describe("PoliciesPage — tabs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetPolicies.mockResolvedValue([]);
  });

  it("shows GUI Builder tab by default", () => {
    renderPage();
    expect(
      screen.getByText("GUI Builder"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Code Editor"),
    ).toBeInTheDocument();
    // GUI form should be visible
    expect(
      screen.getByPlaceholderText("s3_21"),
    ).toBeInTheDocument();
  });

  it("switches to Code Editor tab", () => {
    renderPage();
    fireEvent.click(
      screen.getByText("Code Editor"),
    );
    // Code editor fields visible
    expect(
      screen.getByPlaceholderText(
        "custom_check.rego",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Insert starter template"),
    ).toBeInTheDocument();
    // GUI form fields hidden
    expect(
      screen.queryByPlaceholderText("s3_21"),
    ).not.toBeInTheDocument();
  });

  it("switches back to GUI tab", () => {
    renderPage();
    fireEvent.click(
      screen.getByText("Code Editor"),
    );
    fireEvent.click(
      screen.getByText("GUI Builder"),
    );
    expect(
      screen.getByPlaceholderText("s3_21"),
    ).toBeInTheDocument();
  });

  it("inserts template in code editor", () => {
    renderPage();
    fireEvent.click(
      screen.getByText("Code Editor"),
    );
    // Select a domain first
    const domainSelect = document.querySelector(
      'select[name="domain"]',
    ) as HTMLSelectElement;
    fireEvent.change(domainSelect, {
      target: { value: "network" },
    });
    fireEvent.click(
      screen.getByText("Insert starter template"),
    );
    const textarea = document.querySelector(
      'textarea[name="rego_code"]',
    ) as HTMLTextAreaElement;
    expect(textarea.value).toContain(
      "package aws.network",
    );
    expect(textarea.value).toContain(
      "violations contains",
    );
  });
});

describe("PoliciesPage — GUI form preview", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetPolicies.mockResolvedValue([]);
  });

  it("shows Rego preview when required fields are filled", async () => {
    renderPage();
    // Fill check_id
    const checkIdInput = document.querySelector(
      'input[name="check_id"]',
    ) as HTMLInputElement;
    fireEvent.change(checkIdInput, {
      target: { value: "s3_21" },
    });
    // Fill domain
    const domainSelect = document.querySelector(
      'form select[name="domain"]',
    ) as HTMLSelectElement;
    fireEvent.change(domainSelect, {
      target: { value: "data_protection" },
    });
    // Fill severity
    const severitySelect = document.querySelector(
      'select[name="severity"]',
    ) as HTMLSelectElement;
    fireEvent.change(severitySelect, {
      target: { value: "high" },
    });

    await waitFor(() => {
      expect(
        screen.getByText(
          "Generated Rego Preview",
        ),
      ).toBeInTheDocument();
    });
  });
});

describe("PoliciesPage — view source", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetPolicies.mockResolvedValue(
      mockPolicies,
    );
    mockGetPolicySource.mockResolvedValue({
      check_id: "iam_01",
      filename: "iam.rego",
      rego_code:
        'package aws.identity.iam\n\n"check_id": "iam_01"',
    });
  });

  it("expands source code on view source click", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText("iam_01"),
      ).toBeInTheDocument();
    });
    // Find the view source button (title="View source")
    const viewBtns = screen.getAllByTitle(
      "View source",
    );
    fireEvent.click(viewBtns[0]);
    await waitFor(() => {
      expect(
        screen.getByText("iam.rego"),
      ).toBeInTheDocument();
    });
  });
});

describe("PoliciesPage — submit raw policy", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetPolicies.mockResolvedValue([]);
    mockCreateRawPolicy.mockResolvedValue({
      status: "created",
      check_ids: ["custom_01"],
    });
  });

  it("submits raw rego code", async () => {
    renderPage();
    fireEvent.click(
      screen.getByText("Code Editor"),
    );

    // Fill domain
    const domainSelect = document.querySelector(
      'select[name="domain"]',
    ) as HTMLSelectElement;
    fireEvent.change(domainSelect, {
      target: { value: "identity" },
    });

    // Fill filename
    const filenameInput = document.querySelector(
      'input[name="filename"]',
    ) as HTMLInputElement;
    fireEvent.change(filenameInput, {
      target: { value: "my_check.rego" },
    });

    // Insert template then modify (ensures
    // rego_code state is set via React handler)
    fireEvent.click(
      screen.getByText("Insert starter template"),
    );

    // Submit — the code tab form
    const form = domainSelect.closest("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(
        mockCreateRawPolicy,
      ).toHaveBeenCalledTimes(1);
    });
    const callArg =
      mockCreateRawPolicy.mock.calls[0][0];
    expect(callArg.domain).toBe("identity");
    expect(callArg.filename).toBe(
      "my_check.rego",
    );
    expect(callArg.rego_code).toContain(
      "violations contains",
    );
  });
});
