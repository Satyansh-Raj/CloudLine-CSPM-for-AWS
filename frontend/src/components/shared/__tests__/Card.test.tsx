import { render, screen } from "@testing-library/react";
import Card from "../Card";

describe("Card", () => {
  it("renders children", () => {
    render(<Card>Content</Card>);
    expect(screen.getByText("Content")).toBeInTheDocument();
  });

  it("defaults to stadium variant (rounded-hero)", () => {
    const { container } = render(<Card>Body</Card>);
    expect(container.firstChild as HTMLElement).toHaveClass(
      "rounded-hero",
    );
  });

  it("pill variant uses rounded-pill", () => {
    const { container } = render(
      <Card variant="pill">Body</Card>,
    );
    expect(container.firstChild as HTMLElement).toHaveClass(
      "rounded-pill",
    );
  });

  it("has elev-2 shadow", () => {
    const { container } = render(<Card>Body</Card>);
    expect(
      (container.firstChild as HTMLElement).className,
    ).toContain("shadow-elev-2");
  });

  it("merges extra className", () => {
    const { container } = render(
      <Card className="extra">Body</Card>,
    );
    expect(
      (container.firstChild as HTMLElement).className,
    ).toContain("extra");
  });
});
