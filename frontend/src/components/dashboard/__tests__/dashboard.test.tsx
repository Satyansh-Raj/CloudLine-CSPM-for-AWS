import { render, screen } from "@testing-library/react";
import ComplianceScoreDonut from "../ComplianceScoreDonut";
import DomainDonut from "../DomainDonut";
import SeverityBar from "../SeverityBar";
import RiskCards from "../RiskCards";

// Recharts uses ResizeObserver; stub it
vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);

const complianceData = {
  score_percent: 85,
  passed: 17,
  failed: 3,
  errors: 0,
  skipped: 0,
  by_domain: {},
  by_severity: {},
};

describe("ComplianceScoreDonut", () => {
  it("renders score percentage", () => {
    render(
      <ComplianceScoreDonut data={complianceData} />,
    );
    expect(screen.getByText("85%")).toBeInTheDocument();
  });

  it("renders heading", () => {
    render(
      <ComplianceScoreDonut data={complianceData} />,
    );
    expect(
      screen.getByText("Compliance Score"),
    ).toBeInTheDocument();
  });

  it("renders legend items", () => {
    render(
      <ComplianceScoreDonut data={complianceData} />,
    );
    expect(
      screen.getByText("Passed"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Violations"),
    ).toBeInTheDocument();
  });
});

describe("DomainDonut", () => {
  it("renders heading", () => {
    render(<DomainDonut domains={{}} />);
    expect(
      screen.getByText("Failures by Domain"),
    ).toBeInTheDocument();
  });

  it("renders with domain data", () => {
    render(
      <DomainDonut
        domains={{
          identity_access: {
            passed: 4,
            failed: 1,
            total: 5,
            score_percent: 80,
          },
        }}
      />,
    );
    expect(
      screen.getByText("Failures by Domain"),
    ).toBeInTheDocument();
  });
});

describe("SeverityBar", () => {
  it("renders heading", () => {
    render(<SeverityBar bySeverity={{}} />);
    expect(
      screen.getByText("Violations by Severity"),
    ).toBeInTheDocument();
  });
});

describe("RiskCards", () => {
  it("renders risk categories", () => {
    render(
      <RiskCards
        data={{
          total_scored: 20,
          by_category: {
            critical: 2,
            high: 5,
            medium: 8,
            low: 5,
          },
          highest_risk: [],
        }}
      />,
    );
    expect(
      screen.getByText("Risk Summary"),
    ).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(
      screen.getByText("Total scored: 20"),
    ).toBeInTheDocument();
  });

  it("renders highest risk items", () => {
    render(
      <RiskCards
        data={{
          total_scored: 10,
          by_category: {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
          },
          highest_risk: [
            { check_id: "s3_01", risk_score: 95 },
            { check_id: "iam_02", risk_score: 72 },
          ],
        }}
      />,
    );
    expect(
      screen.getByText("s3_01"),
    ).toBeInTheDocument();
    expect(screen.getByText("95")).toBeInTheDocument();
  });
});
