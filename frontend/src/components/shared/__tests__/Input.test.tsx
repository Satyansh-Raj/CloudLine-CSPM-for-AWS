import { render, screen } from "@testing-library/react";
import Input from "../Input";

describe("Input", () => {
  it("renders input element", () => {
    render(<Input />);
    expect(screen.getByRole("textbox")).toBeInTheDocument();
  });

  it("has pill shape class", () => {
    const { container } = render(<Input />);
    expect(container.querySelector("input")!.className).toContain(
      "rounded-pill",
    );
  });

  it("renders label when provided", () => {
    render(<Input id="email" label="Email" />);
    expect(screen.getByText("Email")).toBeInTheDocument();
  });

  it("associates label with input via id", () => {
    render(<Input id="email" label="Email" />);
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
  });

  it("renders error message", () => {
    render(<Input error="Required" />);
    expect(screen.getByText("Required")).toBeInTheDocument();
  });

  it("adds error border class when error present", () => {
    const { container } = render(<Input error="Bad" />);
    expect(container.querySelector("input")!.className).toContain(
      "border-signal-orange",
    );
  });

  it("forwards placeholder", () => {
    render(<Input placeholder="Enter value" />);
    expect(
      screen.getByPlaceholderText("Enter value"),
    ).toBeInTheDocument();
  });

  it("forwards ref", () => {
    const ref = { current: null } as React.RefObject<HTMLInputElement>;
    render(<Input ref={ref} />);
    expect(ref.current).toBeInstanceOf(HTMLInputElement);
  });
});
