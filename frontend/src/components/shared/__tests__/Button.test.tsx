import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Button from "../Button";

describe("Button", () => {
  it("renders children", () => {
    render(<Button>Click me</Button>);
    expect(screen.getByRole("button", { name: "Click me" })).toBeInTheDocument();
  });

  it("defaults to ink variant with rounded-btn", () => {
    const { container } = render(<Button>Go</Button>);
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain("bg-ink-black");
    expect(btn.className).toContain("rounded-btn");
  });

  it("outline variant has border class", () => {
    const { container } = render(
      <Button variant="outline">Go</Button>,
    );
    expect(container.querySelector("button")!.className).toContain(
      "border-ink-black",
    );
  });

  it("orange variant has signal-orange bg", () => {
    const { container } = render(
      <Button variant="orange">Confirm</Button>,
    );
    expect(container.querySelector("button")!.className).toContain(
      "bg-signal-orange",
    );
  });

  it("intent=consent forces orange regardless of variant", () => {
    const { container } = render(
      <Button variant="ink" intent="consent">
        Agree
      </Button>,
    );
    expect(container.querySelector("button")!.className).toContain(
      "bg-signal-orange",
    );
  });

  it("forwards disabled state", () => {
    render(<Button disabled>Go</Button>);
    expect(screen.getByRole("button")).toBeDisabled();
  });

  it("calls onClick handler", async () => {
    const handler = vi.fn();
    render(<Button onClick={handler}>Click</Button>);
    await userEvent.click(screen.getByRole("button"));
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("merges extra className", () => {
    const { container } = render(
      <Button className="my-class">Go</Button>,
    );
    expect(container.querySelector("button")!.className).toContain(
      "my-class",
    );
  });
});
