import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import CategoryResourcesPage from "../CategoryResourcesPage";

const mockInventory = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks/useInventory", () => ({
  useInventory: () => mockInventory,
}));

vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => ({
    selectedRegion: "",
    regions: ["ap-south-1"],
    isLoading: false,
    setSelectedRegion: vi.fn(),
  }),
}));

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "",
    accounts: [],
    isLoading: false,
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

function renderPage(category = "storage") {
  return render(
    <MemoryRouter initialEntries={[`/inventory/${category}`]}>
      <Routes>
        <Route
          path="/inventory/:category"
          element={<CategoryResourcesPage />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("CategoryResourcesPage", () => {
  afterEach(() => {
    mockInventory.data = null;
    mockInventory.isLoading = false;
    mockInventory.error = null;
  });

  it("shows category name as heading", () => {
    renderPage("storage");
    expect(screen.getByText("Storage")).toBeInTheDocument();
  });

  it("shows back link to inventory", () => {
    renderPage();
    const link = screen.getByRole("link", {
      name: /back to inventory/i,
    });
    expect(link).toHaveAttribute("href", "/inventory");
  });

  it("shows loading state", () => {
    mockInventory.isLoading = true;
    const { container } = renderPage();
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows error state", () => {
    mockInventory.error = { message: "Server error" };
    renderPage();
    expect(screen.getByText(/server error/i)).toBeInTheDocument();
  });

  it("renders resource rows with names", () => {
    mockInventory.data = [
      {
        resource_id: "arn:aws:s3:::prod-bucket",
        resource_name: "prod-bucket",
        resource_type: "s3_bucket",
        technology_category: "storage",
        service: "s3",
        region: "ap-south-1",
        account_id: "832843292195",
        exposure: "internet",
        environment: "prod",
        created_at: "2026-03-01T10:00:00Z",
        violation_count: 3,
        risk_score: 85,
      },
      {
        resource_id: "arn:aws:s3:::logs-bucket",
        resource_name: "logs-bucket",
        resource_type: "s3_bucket",
        technology_category: "storage",
        service: "s3",
        region: "ap-south-1",
        account_id: "832843292195",
        exposure: "private",
        environment: "prod",
        created_at: "2026-03-01T10:00:00Z",
        violation_count: 0,
        risk_score: 10,
      },
    ];
    renderPage("storage");
    expect(screen.getByText("prod-bucket")).toBeInTheDocument();
    expect(screen.getByText("logs-bucket")).toBeInTheDocument();
  });

  it("renders resource rows as links to detail page", () => {
    mockInventory.data = [
      {
        resource_id: "arn:aws:s3:::prod-bucket",
        resource_name: "prod-bucket",
        resource_type: "s3_bucket",
        technology_category: "storage",
        service: "s3",
        region: "ap-south-1",
        account_id: "832843292195",
        exposure: "internet",
        environment: "prod",
        violation_count: 3,
        risk_score: 85,
      },
    ];
    renderPage("storage");
    const link = screen.getByRole("link", {
      name: /prod-bucket/i,
    });
    expect(link).toHaveAttribute(
      "href",
      expect.stringContaining("/inventory/detail"),
    );
  });

  it("shows violation count and risk score", () => {
    mockInventory.data = [
      {
        resource_id: "arn:aws:s3:::prod-bucket",
        resource_name: "prod-bucket",
        resource_type: "s3_bucket",
        technology_category: "storage",
        service: "s3",
        region: "ap-south-1",
        account_id: "832843292195",
        exposure: "internet",
        environment: "prod",
        violation_count: 3,
        risk_score: 85,
      },
    ];
    renderPage("storage");
    expect(screen.getByText(/3 violations/i)).toBeInTheDocument();
    expect(screen.getByText("85")).toBeInTheDocument();
  });

  it("shows empty state when no resources", () => {
    mockInventory.data = [];
    renderPage("storage");
    expect(screen.getByText(/no.*resources/i)).toBeInTheDocument();
  });

  it("renders region dropdown with options from hook", () => {
    renderPage("storage");
    expect(screen.getByText("All Regions")).toBeInTheDocument();
    expect(screen.getByText("ap-south-1")).toBeInTheDocument();
  });
});
