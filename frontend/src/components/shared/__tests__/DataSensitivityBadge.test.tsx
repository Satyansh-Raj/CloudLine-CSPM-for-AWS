import { render, screen } from "@testing-library/react";
import DataSensitivityBadge from "../DataSensitivityBadge";

describe("DataSensitivityBadge", () => {
  it.each(["High", "Medium", "Low"])(
    "renders %s severity text",
    (sev) => {
      render(<DataSensitivityBadge severity={sev} />);
      expect(screen.getByText(sev)).toBeInTheDocument();
    },
  );

  it("renders High with red classes", () => {
    const { container } = render(
      <DataSensitivityBadge severity="High" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-red-100");
  });

  it("renders Medium with yellow classes", () => {
    const { container } = render(
      <DataSensitivityBadge severity="Medium" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-yellow-100");
  });

  it("renders Low with green classes", () => {
    const { container } = render(
      <DataSensitivityBadge severity="Low" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-green-100");
  });

  it("renders unknown severity with gray fallback", () => {
    const { container } = render(
      <DataSensitivityBadge severity="Unknown" />,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-gray-100");
  });
});
