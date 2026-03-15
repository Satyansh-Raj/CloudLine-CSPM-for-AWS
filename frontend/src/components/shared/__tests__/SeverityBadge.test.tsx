import { render, screen } from "@testing-library/react";
import SeverityBadge from "../SeverityBadge";

describe("SeverityBadge", () => {
  it.each(["critical", "high", "medium", "low"])(
    "renders %s severity with correct text",
    (sev) => {
      render(<SeverityBadge severity={sev} />);
      expect(screen.getByText(sev)).toBeInTheDocument();
    },
  );

  it("renders critical with red classes", () => {
    const { container } = render(
      <SeverityBadge severity="critical" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-red-100");
  });

  it("renders high with orange classes", () => {
    const { container } = render(
      <SeverityBadge severity="high" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-orange-100");
  });

  it("renders unknown severity with gray fallback", () => {
    const { container } = render(
      <SeverityBadge severity="unknown" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-gray-100");
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });

  it("has capitalize class", () => {
    const { container } = render(
      <SeverityBadge severity="low" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("capitalize");
  });
});
