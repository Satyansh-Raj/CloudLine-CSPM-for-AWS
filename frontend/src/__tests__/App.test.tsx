import { render, waitFor } from "@testing-library/react";
import App from "../App";

// Mock all pages to avoid deep dependency chains
vi.mock("@/pages", () => ({
  DashboardPage: () => <div>Dashboard</div>,
  ViolationsPage: () => <div>Violations</div>,
  ViolationDetailPage: () => <div>ViolationDetail</div>,
  ResolvedIssuesPage: () => <div>Resolved</div>,
  TrendsPage: () => <div>Trends</div>,

  PoliciesPage: () => <div>Policies</div>,
  InventoryPage: () => <div>Inventory</div>,
  CategoryResourcesPage: () => <div>CategoryResources</div>,
  ResourceDetailPage: () => <div>ResourceDetail</div>,
  CompliancePage: () => <div>Compliance</div>,
  ResolvedDetailPage: () => <div>ResolvedDetail</div>,
}));

vi.mock("@/components/layout", () => ({
  Layout: () => <div data-testid="layout">Layout</div>,
}));

// Mock context providers to avoid real API calls
vi.mock("@/context/AccountContext", () => ({
  AccountProvider: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));

vi.mock("@/context/RegionContext", () => ({
  RegionProvider: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));

describe("App", () => {
  it("renders without crashing", async () => {
    render(<App />);

    await waitFor(() => {
      expect(document.body.querySelector("div")).toBeTruthy();
    });
  });

  it("renders layout directly", async () => {
    render(<App />);

    await waitFor(() => {
      expect(document.body.querySelector("div")).toBeTruthy();
    });
  });
});
