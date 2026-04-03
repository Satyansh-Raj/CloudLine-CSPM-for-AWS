import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import InventoryPage from "../InventoryPage";

const mockSummary = {
  data: null as unknown,
  isLoading: false,
  error: null as unknown,
};

let capturedSummaryArgs: unknown[] = [];

vi.mock("@/hooks/useInventory", () => ({
  useInventory: () => ({
    data: null,
    isLoading: false,
    error: null,
  }),
  useInventorySummary: (...args: unknown[]) => {
    capturedSummaryArgs = args;
    return mockSummary;
  },
}));

vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => ({
    selectedRegion: "",
    regions: ["ap-south-1"],
    isLoading: false,
    setSelectedRegion: vi.fn(),
  }),
}));

let mockInventorySelectedAccount = "";

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: mockInventorySelectedAccount,
    accounts: [],
    isLoading: false,
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <InventoryPage />
    </MemoryRouter>,
  );
}

describe("InventoryPage", () => {
  afterEach(() => {
    mockSummary.data = null;
    mockSummary.isLoading = false;
    mockSummary.error = null;
  });

  it("shows heading", () => {
    renderPage();
    expect(screen.getByText("Inventory")).toBeInTheDocument();
  });

  it("shows loading state", () => {
    mockSummary.isLoading = true;
    const { container } = renderPage();
    expect(container.querySelector(".animate-pulse")).toBeTruthy();
  });

  it("shows error state", () => {
    mockSummary.error = { message: "API down" };
    renderPage();
    expect(screen.getByText(/api down/i)).toBeInTheDocument();
  });

  it("renders category cards from summary", () => {
    mockSummary.data = {
      total: 42,
      by_category: {
        storage: 15,
        compute: 10,
        database: 8,
        identity: 9,
      },
      by_exposure: { internet: 8, private: 34 },
      by_service: { s3: 15, ec2: 10 },
    };
    renderPage();
    expect(screen.getByText("Storage")).toBeInTheDocument();
    expect(screen.getByText("Compute")).toBeInTheDocument();
    expect(screen.getByText("Database")).toBeInTheDocument();
    expect(screen.getByText("Identity")).toBeInTheDocument();
  });

  it("shows resource count per category card", () => {
    mockSummary.data = {
      total: 25,
      by_category: { storage: 15, compute: 10 },
      by_exposure: {},
      by_service: {},
    };
    renderPage();
    expect(screen.getByText("15")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
  });

  it("renders category cards as links to /inventory/:category", () => {
    mockSummary.data = {
      total: 5,
      by_category: { storage: 5 },
      by_exposure: {},
      by_service: {},
    };
    renderPage();
    const link = screen.getByRole("link", {
      name: /storage/i,
    });
    expect(link).toHaveAttribute("href", "/inventory/storage");
  });

  it("shows total resources stat", () => {
    mockSummary.data = {
      total: 42,
      by_category: { storage: 30, compute: 12 },
      by_exposure: { internet: 8, private: 34 },
      by_service: {},
    };
    renderPage();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("shows empty state when no categories", () => {
    mockSummary.data = {
      total: 0,
      by_category: {},
      by_exposure: {},
      by_service: {},
    };
    renderPage();
    expect(screen.getByText(/no resources found/i)).toBeInTheDocument();
  });

  it("renders icons in category cards", () => {
    mockSummary.data = {
      total: 5,
      by_category: { storage: 5 },
      by_exposure: {},
      by_service: {},
    };
    const { container } = renderPage();
    const imgs = container.querySelectorAll("img");
    expect(imgs.length).toBeGreaterThanOrEqual(1);
  });
});

describe("InventoryPage account wiring", () => {
  beforeEach(() => {
    capturedSummaryArgs = [];
    mockInventorySelectedAccount = "";
  });

  afterEach(() => {
    mockInventorySelectedAccount = "";
    mockSummary.data = null;
    mockSummary.isLoading = false;
    mockSummary.error = null;
  });

  it("passes no account_id when selectedAccount is empty", () => {
    mockInventorySelectedAccount = "";
    renderPage();
    // second arg should be undefined or not present
    expect(capturedSummaryArgs[1]).toBeUndefined();
  });

  it("passes account_id to useInventorySummary when account selected", () => {
    mockInventorySelectedAccount = "111111111111";
    renderPage();
    expect(capturedSummaryArgs[1]).toBe("111111111111");
  });
});
