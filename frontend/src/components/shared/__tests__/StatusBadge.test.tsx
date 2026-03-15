import { render, screen } from "@testing-library/react";
import StatusBadge from "../StatusBadge";

describe("StatusBadge", () => {
  it.each(["alarm", "ok", "error", "skip"])(
    "renders %s status with correct text",
    (status) => {
      render(<StatusBadge status={status} />);
      expect(
        screen.getByText(status),
      ).toBeInTheDocument();
    },
  );

  it("renders alarm with red classes", () => {
    const { container } = render(
      <StatusBadge status="alarm" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-red-100");
  });

  it("renders ok with green classes", () => {
    const { container } = render(
      <StatusBadge status="ok" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-green-100");
  });

  it("renders unknown status with gray fallback", () => {
    const { container } = render(
      <StatusBadge status="other" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-gray-100");
  });

  it("has uppercase class", () => {
    const { container } = render(
      <StatusBadge status="ok" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("uppercase");
  });
});
