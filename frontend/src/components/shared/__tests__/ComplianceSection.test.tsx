import { render, screen } from "@testing-library/react";
import ComplianceSection from "../ComplianceSection";

describe("ComplianceSection", () => {
  it("renders the label", () => {
    render(
      <ComplianceSection label="CIS AWS" controls={["2.1.4"]} />,
    );
    expect(screen.getByText("CIS AWS")).toBeInTheDocument();
  });

  it("renders a single control as a badge", () => {
    render(
      <ComplianceSection label="NIST 800-53" controls={["AC-3"]} />,
    );
    expect(screen.getByText("AC-3")).toBeInTheDocument();
  });

  it("renders multiple controls as separate badges", () => {
    render(
      <ComplianceSection
        label="PCI DSS"
        controls={["8.3.1", "8.3.2", "10.2.1"]}
      />,
    );
    expect(screen.getByText("8.3.1")).toBeInTheDocument();
    expect(screen.getByText("8.3.2")).toBeInTheDocument();
    expect(screen.getByText("10.2.1")).toBeInTheDocument();
  });

  it("renders nothing when controls array is empty", () => {
    const { container } = render(
      <ComplianceSection label="SOC 2" controls={[]} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("does not render the label when controls is empty", () => {
    render(<ComplianceSection label="HIPAA" controls={[]} />);
    expect(screen.queryByText("HIPAA")).not.toBeInTheDocument();
  });

  it("renders each control badge with its own key (no duplicates)", () => {
    render(
      <ComplianceSection
        label="CIS AWS"
        controls={["1.1", "1.2"]}
      />,
    );
    const badges = screen.getAllByText(/^1\.[12]$/);
    expect(badges).toHaveLength(2);
  });
});
