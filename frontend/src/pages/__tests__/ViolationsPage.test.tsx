import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import ViolationsPage from "../ViolationsPage";

const mockViolations = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useViolations: () => mockViolations,
}));

vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => ({
    selectedRegion: "",
    regions: ["ap-south-1", "us-east-1"],
    isLoading: false,
    setSelectedRegion: vi.fn(),
  }),
}));

vi.mock("@/components/violations", () => ({
  ViolationsTable: ({ data }: { data: unknown[] }) => (
    <div data-testid="table">{data.length} rows</div>
  ),
  ViolationFilters: () => <div data-testid="filters" />,
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <ViolationsPage />
    </MemoryRouter>,
  );
}

describe("ViolationsPage", () => {
  afterEach(() => {
    mockViolations.data = null;
    mockViolations.isLoading = false;
    mockViolations.error = null;
  });

  it("shows heading", () => {
    renderPage();
    expect(screen.getByText("Violations")).toBeInTheDocument();
  });

  it("shows loading state", () => {
    mockViolations.isLoading = true;
    const { container } = renderPage();
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows error state", () => {
    mockViolations.error = { message: "API down" };
    renderPage();
    expect(screen.getByText(/api down/i)).toBeInTheDocument();
  });

  it("shows table with data", () => {
    mockViolations.data = [
      {
        check_id: "s3_block_public_acls",
        severity: "critical",
        status: "alarm",
      },
    ];
    renderPage();
    expect(screen.getByTestId("table")).toBeInTheDocument();
  });

  it("renders filters", () => {
    renderPage();
    expect(screen.getByTestId("filters")).toBeInTheDocument();
  });

  it("renders region dropdown with label", () => {
    renderPage();
    expect(screen.getByText("Region")).toBeInTheDocument();
    expect(screen.getByText("All Regions")).toBeInTheDocument();
  });

  it("shows regions from context in dropdown", () => {
    renderPage();
    expect(screen.getByText("ap-south-1")).toBeInTheDocument();
    expect(screen.getByText("us-east-1")).toBeInTheDocument();
  });
});
