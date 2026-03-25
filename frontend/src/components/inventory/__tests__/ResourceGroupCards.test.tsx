import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ResourceGroupCards from "../ResourceGroupCards";
import type { Resource } from "@/types/inventory";

const mockResources: Resource[] = [
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
    owner: "team-data",
    tags: { env: "prod" },
    is_active: true,
    last_seen: "2026-03-18T10:00:00Z",
    violation_count: 3,
    critical_violations: 1,
    high_violations: 2,
    risk_score: 85,
    connected_to: [],
    managed_by: null,
    belongs_to: null,
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
    owner: "",
    tags: {},
    is_active: true,
    last_seen: "2026-03-18T10:00:00Z",
    violation_count: 0,
    critical_violations: 0,
    high_violations: 0,
    risk_score: 10,
    connected_to: [],
    managed_by: null,
    belongs_to: null,
  },
  {
    resource_id: "arn:aws:ec2:ap-south-1:832843292195:instance/i-abc123",
    resource_name: "web-server-1",
    resource_type: "ec2_instance",
    technology_category: "compute",
    service: "ec2",
    region: "ap-south-1",
    account_id: "832843292195",
    exposure: "internet",
    environment: "prod",
    owner: "team-infra",
    tags: { Name: "web-server-1" },
    is_active: true,
    last_seen: "2026-03-18T10:00:00Z",
    violation_count: 1,
    critical_violations: 0,
    high_violations: 1,
    risk_score: 55,
    connected_to: [],
    managed_by: null,
    belongs_to: null,
  },
  {
    resource_id: "arn:aws:rds:ap-south-1:832843292195:db:prod-db",
    resource_name: "prod-db",
    resource_type: "rds_instance",
    technology_category: "database",
    service: "rds",
    region: "ap-south-1",
    account_id: "832843292195",
    exposure: "private",
    environment: "prod",
    owner: "team-data",
    tags: {},
    is_active: true,
    last_seen: "2026-03-18T10:00:00Z",
    violation_count: 2,
    critical_violations: 1,
    high_violations: 1,
    risk_score: 72,
    connected_to: [],
    managed_by: null,
    belongs_to: null,
  },
  {
    resource_id: "arn:aws:iam::832843292195:user/admin",
    resource_name: "admin",
    resource_type: "iam_user",
    technology_category: "identity",
    service: "iam",
    region: "ap-south-1",
    account_id: "832843292195",
    exposure: "unknown",
    environment: "unknown",
    owner: "",
    tags: {},
    is_active: true,
    last_seen: "2026-03-18T10:00:00Z",
    violation_count: 5,
    critical_violations: 2,
    high_violations: 3,
    risk_score: 92,
    connected_to: [],
    managed_by: null,
    belongs_to: null,
  },
];

describe("ResourceGroupCards", () => {
  it("renders category group cards", () => {
    render(<ResourceGroupCards data={mockResources} />);
    expect(screen.getByText("storage")).toBeInTheDocument();
    expect(screen.getByText("compute")).toBeInTheDocument();
    expect(screen.getByText("database")).toBeInTheDocument();
    expect(screen.getByText("identity")).toBeInTheDocument();
  });

  it("shows resource count per category", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // storage has 2 resources, compute 1, database 1,
    // identity 1
    const storageCard = screen.getByText("storage").closest("[data-testid]")!;
    expect(within(storageCard).getByText("2")).toBeInTheDocument();
  });

  it("displays resource names within each group", () => {
    render(<ResourceGroupCards data={mockResources} />);
    expect(screen.getByText("prod-bucket")).toBeInTheDocument();
    expect(screen.getByText("logs-bucket")).toBeInTheDocument();
    expect(screen.getByText("web-server-1")).toBeInTheDocument();
    expect(screen.getByText("prod-db")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  it("shows violation counts on resources", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // prod-bucket has 3 violations
    const prodBucket = screen
      .getByText("prod-bucket")
      .closest("[data-testid='resource-row']")!;
    expect(within(prodBucket).getByText("3")).toBeInTheDocument();
  });

  it("shows risk score with color coding", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // admin has risk_score 92 (critical — red)
    const adminRow = screen
      .getByText("admin")
      .closest("[data-testid='resource-row']")!;
    const riskEl = within(adminRow).getByTestId("risk-score");
    expect(riskEl).toHaveTextContent("92");
  });

  it("shows exposure badges", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // prod-bucket is internet-exposed
    expect(screen.getAllByText("EXPOSED").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("INTERNAL").length).toBeGreaterThanOrEqual(2);
  });

  it("renders empty state when no resources", () => {
    render(<ResourceGroupCards data={[]} />);
    expect(screen.getByText(/no resources found/i)).toBeInTheDocument();
  });

  it("sorts categories by total violations desc", () => {
    render(<ResourceGroupCards data={mockResources} />);
    const cards = screen.getAllByTestId("category-card");
    // identity has 5 violations (highest)
    // storage has 3 total, database 2, compute 1
    expect(cards[0]).toHaveTextContent("identity");
    expect(cards[1]).toHaveTextContent("storage");
  });

  it("shows category-level violation summary", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // identity card should show total violations
    const identityCard = screen
      .getAllByTestId("category-card")
      .find((c) => c.textContent?.includes("identity"))!;
    expect(
      within(identityCard).getByTestId("category-violations"),
    ).toHaveTextContent("5");
  });

  it("shows service label on resources", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // s3 appears twice (2 buckets), rest once
    expect(screen.getAllByText("s3").length).toBe(2);
    expect(screen.getAllByText("ec2").length).toBe(1);
    expect(screen.getAllByText("rds").length).toBe(1);
    expect(screen.getAllByText("iam").length).toBe(1);
  });

  it("calls onCategoryClick when card header is clicked", async () => {
    const onClick = vi.fn();
    render(
      <ResourceGroupCards data={mockResources} onCategoryClick={onClick} />,
    );

    const identityCard = screen
      .getAllByTestId("category-card")
      .find((c) => c.textContent?.includes("identity"))!;

    const header = within(identityCard).getByRole("button");
    await userEvent.click(header);

    expect(onClick).toHaveBeenCalledWith("identity");
  });

  it("does not crash without onCategoryClick", () => {
    render(<ResourceGroupCards data={mockResources} />);
    // Just verifies no crash when prop is omitted
    expect(screen.getAllByTestId("category-card").length).toBe(4);
  });
});
