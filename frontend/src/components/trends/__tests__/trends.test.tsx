import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import PeriodSelector from "../PeriodSelector";
import TrendLineChart from "../TrendLineChart";
import SeverityTrendChart from "../SeverityTrendChart";

vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);

describe("PeriodSelector", () => {
  it("renders all period options", () => {
    render(<PeriodSelector value="7d" onChange={() => {}} />);
    expect(screen.getByText("7 Days")).toBeInTheDocument();
    expect(screen.getByText("30 Days")).toBeInTheDocument();
    expect(screen.getByText("90 Days")).toBeInTheDocument();
  });

  it("highlights active period", () => {
    render(<PeriodSelector value="30d" onChange={() => {}} />);
    const btn = screen.getByText("30 Days");
    expect(btn.className).toContain("bg-ink-black");
  });

  it("calls onChange on click", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<PeriodSelector value="7d" onChange={onChange} />);

    await user.click(screen.getByText("90 Days"));
    expect(onChange).toHaveBeenCalledWith("90d");
  });
});

const mockData = [
  {
    date: "01/01",
    violations: 5,
    resolutions: 3,
    active: 2,
    critical: 1,
    high: 2,
    medium: 1,
    low: 1,
  },
];

describe("TrendLineChart", () => {
  it("renders heading", () => {
    render(<TrendLineChart data={mockData} />);
    expect(screen.getByText("Violations Over Time")).toBeInTheDocument();
  });
});

describe("SeverityTrendChart", () => {
  it("renders heading", () => {
    render(<SeverityTrendChart data={mockData} />);
    expect(screen.getByText("Violations by Severity")).toBeInTheDocument();
  });
});
