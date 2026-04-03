import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import IamGraphPage from "../IamGraphPage";
import type { Violation, IamGraphResponse } from "@/types";

// ── Mock @xyflow/react ────────────────────────────
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="react-flow">{children}</div>
  ),
  Background: () => null,
  useNodesState: (n: unknown) => [n, vi.fn(), vi.fn()],
  useEdgesState: (e: unknown) => [e, vi.fn(), vi.fn()],
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
  Handle: () => null,
  Position: { Top: "top", Bottom: "bottom", Left: "left", Right: "right" },
  MarkerType: { ArrowClosed: "arrowclosed" },
  BackgroundVariant: { Dots: "dots" },
  useReactFlow: () => ({ fitView: vi.fn() }),
}));

vi.mock("@xyflow/react/dist/style.css", () => ({}));

// ── Mock useIamGraph ──────────────────────────────
const mockIamGraph = {
  data: null as IamGraphResponse | null | undefined,
  isLoading: false,
  isError: false,
};

let capturedIamGraphArgs: unknown[] = [];
let mockIamSelectedAccount = "";

vi.mock("@/hooks", () => ({
  useIamGraph: (...args: unknown[]) => {
    capturedIamGraphArgs = args;
    return mockIamGraph;
  },
}));

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: mockIamSelectedAccount,
    accounts: [],
    isLoading: false,
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

// ── Mock buildIamGraph ────────────────────────────
let capturedOnSelect: ((v: Violation) => void) | null = null;

vi.mock("@/utils/iamGraphBuilder", () => ({
  buildIamGraph: vi
    .fn()
    .mockImplementation(
      (
        _resp: unknown,
        _collapsed: unknown,
        _toggle: unknown,
        onSelect: (v: Violation) => void,
      ) => {
        capturedOnSelect = onSelect;
        return { nodes: [], edges: [] };
      },
    ),
  getInitialCollapsedIds: vi.fn().mockReturnValue(new Set<string>()),
}));

// ── Helpers ───────────────────────────────────────

function makeApiData(
  overrides: Partial<IamGraphResponse> = {},
): IamGraphResponse {
  return {
    account_id: "123456",
    users: [
      {
        name: "alice",
        arn: "arn:aws:iam::123:user/alice",
        mfa_enabled: true,
        inline_policies: [],
        attached_policies: [],
        groups: [],
        effective_permissions: {},
        violations: [
          {
            check_id: "iam_user_mfa",
            status: "alarm",
            severity: "high",
            reason: "MFA not enabled",
            risk_score: 72,
          },
        ],
      },
    ],
    account_violations: [],
    ...overrides,
  };
}

function makeViol(overrides: Partial<Violation> = {}): Violation {
  return {
    check_id: "iam_user_mfa",
    status: "alarm",
    severity: "high",
    reason: "MFA not enabled",
    resource: "arn:aws:iam::123:user/alice",
    domain: "identity",
    compliance: {
      cis_aws: ["1.10"],
      nist_800_53: ["IA-2(1)"],
      pci_dss: [],
      hipaa: [],
      soc2: [],
    },
    remediation_id: "iam_user_mfa",
    risk_score: 72,
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <IamGraphPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────

describe("IamGraphPage", () => {
  afterEach(() => {
    mockIamGraph.data = null;
    mockIamGraph.isLoading = false;
    mockIamGraph.isError = false;
    capturedOnSelect = null;
  });

  it("renders heading", () => {
    renderPage();
    expect(screen.getByText("IAM Graph")).toBeInTheDocument();
  });

  it("shows loading skeleton", () => {
    mockIamGraph.isLoading = true;
    const { container } = renderPage();
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows error state", () => {
    mockIamGraph.isError = true;
    renderPage();
    expect(screen.getByText(/failed to load iam data/i)).toBeInTheDocument();
  });

  it("shows empty-state CTA when no data", () => {
    mockIamGraph.data = {
      account_id: "123",
      users: [],
      account_violations: [],
    };
    renderPage();
    expect(
      screen.getByText(/no iam data — run a scan first/i),
    ).toBeInTheDocument();
  });

  it("shows react-flow canvas when data present", () => {
    mockIamGraph.data = makeApiData();
    renderPage();
    expect(screen.getByTestId("react-flow")).toBeInTheDocument();
  });

  it("renders search input", () => {
    renderPage();
    expect(screen.getByPlaceholderText(/search users/i)).toBeInTheDocument();
  });

  it("renders fullscreen button", () => {
    renderPage();
    expect(
      screen.getByRole("button", {
        name: /enter fullscreen/i,
      }),
    ).toBeInTheDocument();
  });

  it("detail panel appears when onSelect called", () => {
    mockIamGraph.data = makeApiData();
    renderPage();

    expect(screen.queryByText("Check Detail")).not.toBeInTheDocument();

    act(() => {
      capturedOnSelect?.(makeViol());
    });

    expect(screen.getByText("Check Detail")).toBeInTheDocument();
  });

  it("detail panel closes on X button", () => {
    mockIamGraph.data = makeApiData();
    renderPage();

    act(() => {
      capturedOnSelect?.(makeViol());
    });

    expect(screen.getByText("Check Detail")).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", {
        name: /close panel/i,
      }),
    );

    expect(screen.queryByText("Check Detail")).not.toBeInTheDocument();
  });

  it("shows no-matches when search filters all", () => {
    mockIamGraph.data = makeApiData();
    renderPage();

    const input = screen.getByPlaceholderText(/search users/i);
    fireEvent.change(input, {
      target: { value: "nonexistent-user" },
    });

    expect(screen.getByText(/no users match your search/i)).toBeInTheDocument();
  });
});
