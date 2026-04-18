import { render, screen } from "@testing-library/react";
import GhostHeadline from "../GhostHeadline";

describe("GhostHeadline", () => {
  it("renders text content", () => {
    const { container } = render(<GhostHeadline>Overview</GhostHeadline>);
    expect(container.textContent).toContain("Overview");
  });

  it("is aria-hidden", () => {
    const { container } = render(<GhostHeadline>Overview</GhostHeadline>);
    expect(container.querySelector("[aria-hidden]")).toBeInTheDocument();
  });

  it("has ghost-cream text class", () => {
    const { container } = render(<GhostHeadline>Overview</GhostHeadline>);
    expect(container.querySelector("span")!.className).toContain(
      "text-ghost-cream",
    );
  });

  it("is absolutely positioned", () => {
    const { container } = render(<GhostHeadline>Overview</GhostHeadline>);
    expect(container.querySelector("span")!.className).toContain("absolute");
  });

  it("merges extra className", () => {
    const { container } = render(
      <GhostHeadline className="top-0">Overview</GhostHeadline>,
    );
    expect(container.querySelector("span")!.className).toContain("top-0");
  });

  it("has select-none to prevent user selection", () => {
    const { container } = render(<GhostHeadline>Hidden</GhostHeadline>);
    expect(container.querySelector("span")!.className).toContain("select-none");
  });
});
