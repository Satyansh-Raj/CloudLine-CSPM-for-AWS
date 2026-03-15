import { render, screen } from "@testing-library/react";
import PlaceholderPage from "../PlaceholderPage";

describe("PlaceholderPage", () => {
  it("renders title", () => {
    render(<PlaceholderPage title="Reports" />);
    expect(
      screen.getByText("Reports"),
    ).toBeInTheDocument();
  });

  it("shows coming soon message", () => {
    render(<PlaceholderPage title="Settings" />);
    expect(
      screen.getByText("Coming soon."),
    ).toBeInTheDocument();
  });
});
