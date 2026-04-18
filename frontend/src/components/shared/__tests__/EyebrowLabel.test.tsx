import { render, screen } from "@testing-library/react";
import EyebrowLabel from "../EyebrowLabel";

describe("EyebrowLabel", () => {
  it("renders text content", () => {
    render(<EyebrowLabel>Security</EyebrowLabel>);
    expect(screen.getByText("Security")).toBeInTheDocument();
  });

  it("renders orange dot", () => {
    const { container } = render(
      <EyebrowLabel>Label</EyebrowLabel>,
    );
    const dot = container.querySelector("[aria-hidden]")!;
    expect(dot.textContent).toBe("•");
    expect(dot.className).toContain("text-light-signal");
  });

  it("has uppercase and tracking-eyebrow classes", () => {
    const { container } = render(
      <EyebrowLabel>Label</EyebrowLabel>,
    );
    const span = container.querySelector("span")!;
    expect(span.className).toContain("uppercase");
    expect(span.className).toContain("tracking-eyebrow");
  });

  it("merges extra className", () => {
    const { container } = render(
      <EyebrowLabel className="mt-2">Label</EyebrowLabel>,
    );
    expect(container.querySelector("span")!.className).toContain(
      "mt-2",
    );
  });
});
