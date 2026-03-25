import {
  render,
  screen,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import SecurityGraphPage from "../SecurityGraphPage";
import type { SecurityGraph } from "@/types/securityGraph";

/* ── Mock @xyflow/react ────────────────────────── */
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({
    children,
  }: {
    children: React.ReactNode;
  }) => (
    <div data-testid="react-flow">{children}</div>
  ),
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  useNodesState: (n: unknown) => [n, vi.fn(), vi.fn()],
  useEdgesState: (e: unknown) => [e, vi.fn(), vi.fn()],
  ReactFlowProvider: ({
    children,
  }: {
    children: React.ReactNode;
  }) => <>{children}</>,
  Handle: () => null,
  Position: {
    Top: "top",
    Bottom: "bottom",
    Left: "left",
    Right: "right",
  },
  MarkerType: { ArrowClosed: "arrowclosed" },
  BackgroundVariant: { Dots: "dots" },
  useReactFlow: () => ({ fitView: vi.fn() }),
}));

vi.mock("@xyflow/react/dist/style.css", () => ({}));

/* ── Mock useSecurityGraph ──────────────────────── */
const mockGraph = {
  data: null as SecurityGraph | null | undefined,
  isLoading: false,
  isError: false,
};

vi.mock("@/hooks/useSecurityGraph", () => ({
  useSecurityGraph: () => mockGraph,
}));

/* ── Mock useRegion ──────────────────────────────── */
vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => ({
    selectedRegion: "",
    regions: ["ap-south-1", "us-east-1"],
    setSelectedRegion: vi.fn(),
  }),
}));

/* ── Mock useAccount ─────────────────────────────── */
vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "",
    accounts: [],
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

/* ── Helpers ─────────────────────────────────────── */

function makeGraph(
  overrides: Partial<SecurityGraph> = {},
): SecurityGraph {
  return {
    nodes: [],
    edges: [],
    attack_paths: 0,
    total_nodes: 0,
    total_edges: 0,
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <SecurityGraphPage />
    </MemoryRouter>,
  );
}

/* ── Tests ───────────────────────────────────────── */

describe("SecurityGraphPage", () => {
  afterEach(() => {
    mockGraph.data = null;
    mockGraph.isLoading = false;
    mockGraph.isError = false;
  });

  it("renders page title 'Security Graph'", () => {
    renderPage();
    expect(
      screen.getByText("Security Graph"),
    ).toBeInTheDocument();
  });

  it("renders page subtitle", () => {
    renderPage();
    expect(
      screen.getByText(
        /resource relationships/i,
      ),
    ).toBeInTheDocument();
  });

  it("shows loading skeleton while fetching", () => {
    mockGraph.isLoading = true;
    const { container } = renderPage();
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeTruthy();
  });

  it("shows error message on error", () => {
    mockGraph.isError = true;
    renderPage();
    expect(
      screen.getByText(/failed to load/i),
    ).toBeInTheDocument();
  });

  it("shows graph container with data-testid when data present", () => {
    mockGraph.data = makeGraph({
      total_nodes: 5,
      total_edges: 4,
      attack_paths: 1,
      nodes: [
        {
          id: "arn:aws:s3:::my-bucket",
          label: "my-bucket",
          resource_type: "s3_bucket",
          service: "s3",
          region: "ap-south-1",
          violation_count: 2,
          max_severity: "high",
          risk_score: 45,
        },
      ],
    });
    renderPage();
    expect(
      screen.getByTestId("security-graph-container"),
    ).toBeInTheDocument();
  });

  it("stats bar shows total nodes count", () => {
    mockGraph.data = makeGraph({ total_nodes: 15 });
    renderPage();
    expect(screen.getByText("15")).toBeInTheDocument();
    expect(
      screen.getByText("Total Nodes"),
    ).toBeInTheDocument();
  });

  it("stats bar shows total edges count", () => {
    mockGraph.data = makeGraph({ total_edges: 10 });
    renderPage();
    expect(screen.getByText("10")).toBeInTheDocument();
    expect(
      screen.getByText("Total Edges"),
    ).toBeInTheDocument();
  });

  it("stats bar shows attack paths count", () => {
    mockGraph.data = makeGraph({ attack_paths: 3 });
    renderPage();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(
      screen.getByText("Attack Paths"),
    ).toBeInTheDocument();
  });

  it("region selector is present", () => {
    renderPage();
    expect(
      screen.getByRole("combobox", { name: /region/i }),
    ).toBeInTheDocument();
  });

  it("shows empty state when no nodes", () => {
    mockGraph.data = makeGraph({
      nodes: [],
      total_nodes: 0,
    });
    renderPage();
    expect(
      screen.getByText(/no resources found/i),
    ).toBeInTheDocument();
  });

  it("renders react-flow canvas when data has nodes", () => {
    mockGraph.data = makeGraph({
      total_nodes: 1,
      nodes: [
        {
          id: "arn:aws:ec2:::i-123",
          label: "my-instance",
          resource_type: "ec2_instance",
          service: "ec2",
          region: "ap-south-1",
          violation_count: 0,
          max_severity: "none",
          risk_score: 0,
        },
      ],
    });
    renderPage();
    expect(
      screen.getByTestId("react-flow"),
    ).toBeInTheDocument();
  });
});
