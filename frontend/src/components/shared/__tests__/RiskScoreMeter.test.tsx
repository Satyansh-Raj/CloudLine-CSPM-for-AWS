import { render, screen } from "@testing-library/react";
import RiskScoreMeter from "../RiskScoreMeter";

describe("RiskScoreMeter", () => {
  it("renders the score value", () => {
    render(<RiskScoreMeter score={85} />);
    expect(screen.getByText("85")).toBeInTheDocument();
  });

  it('renders "/ 100" suffix', () => {
    render(<RiskScoreMeter score={42} />);
    expect(screen.getByText("/ 100")).toBeInTheDocument();
  });

  it('renders "Risk Score" heading', () => {
    render(<RiskScoreMeter score={10} />);
    expect(screen.getByText("Risk Score")).toBeInTheDocument();
  });

  it('renders "Critical Risk" label for score >= 76', () => {
    render(<RiskScoreMeter score={76} />);
    expect(screen.getByText("Critical Risk")).toBeInTheDocument();
  });

  it('renders "Critical Risk" label for score = 100', () => {
    render(<RiskScoreMeter score={100} />);
    expect(screen.getByText("Critical Risk")).toBeInTheDocument();
  });

  it('renders "High Risk" label for score = 75 (boundary)', () => {
    render(<RiskScoreMeter score={75} />);
    expect(screen.getByText("High Risk")).toBeInTheDocument();
  });

  it('renders "High Risk" label for score = 51', () => {
    render(<RiskScoreMeter score={51} />);
    expect(screen.getByText("High Risk")).toBeInTheDocument();
  });

  it('renders "Medium Risk" label for score = 50 (boundary)', () => {
    render(<RiskScoreMeter score={50} />);
    expect(screen.getByText("Medium Risk")).toBeInTheDocument();
  });

  it('renders "Medium Risk" label for score = 26', () => {
    render(<RiskScoreMeter score={26} />);
    expect(screen.getByText("Medium Risk")).toBeInTheDocument();
  });

  it('renders "Low Risk" label for score = 25 (boundary)', () => {
    render(<RiskScoreMeter score={25} />);
    expect(screen.getByText("Low Risk")).toBeInTheDocument();
  });

  it('renders "Low Risk" label for score = 0', () => {
    render(<RiskScoreMeter score={0} />);
    expect(screen.getByText("Low Risk")).toBeInTheDocument();
  });

  it("renders progress bar with correct width style", () => {
    const { container } = render(<RiskScoreMeter score={60} />);
    const bar = container.querySelector(
      "[style]",
    ) as HTMLElement;
    expect(bar).not.toBeNull();
    expect(bar.style.width).toBe("60%");
  });

  it("renders progress bar with 0% width for score 0", () => {
    const { container } = render(<RiskScoreMeter score={0} />);
    const bar = container.querySelector(
      "[style]",
    ) as HTMLElement;
    expect(bar).not.toBeNull();
    expect(bar.style.width).toBe("0%");
  });

  it("renders progress bar with 100% width for score 100", () => {
    const { container } = render(<RiskScoreMeter score={100} />);
    const bar = container.querySelector(
      "[style]",
    ) as HTMLElement;
    expect(bar).not.toBeNull();
    expect(bar.style.width).toBe("100%");
  });
});
