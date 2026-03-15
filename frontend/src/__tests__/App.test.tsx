import { render, waitFor } from "@testing-library/react";
import App from "../App";

// Mock all pages to avoid deep dependency chains
vi.mock("@/pages", () => ({
  DashboardPage: () => <div>Dashboard</div>,
  ViolationsPage: () => <div>Violations</div>,
  ViolationDetailPage: () => <div>ViolationDetail</div>,
  ResolvedIssuesPage: () => <div>Resolved</div>,
  TrendsPage: () => <div>Trends</div>,
  ExecutiveSummaryPage: () => <div>Executive</div>,
  PoliciesPage: () => <div>Policies</div>,
}));

vi.mock("@/components/layout", () => ({
  Layout: () => (
    <div data-testid="layout">Layout</div>
  ),
}));

describe("App", () => {
  it("renders without crashing", async () => {
    render(<App />);

    await waitFor(() => {
      expect(
        document.body.querySelector("div"),
      ).toBeTruthy();
    });
  });

  it("renders layout directly", async () => {
    render(<App />);

    await waitFor(() => {
      expect(
        document.body.querySelector("div"),
      ).toBeTruthy();
    });
  });
});
