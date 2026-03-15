import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Sidebar from "../Sidebar";

function renderSidebar() {
  return render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>,
  );
}

describe("Sidebar", () => {
  it("renders CloudLine branding", () => {
    renderSidebar();
    expect(
      screen.getByText("CloudLine"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("AWS Security"),
    ).toBeInTheDocument();
  });

  it("renders nav links", () => {
    renderSidebar();
    expect(
      screen.getByText("Dashboard"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Violations"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Trends"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Executive"),
    ).toBeInTheDocument();
  });

  it("shows version", () => {
    renderSidebar();
    expect(
      screen.getByText("v0.1.0"),
    ).toBeInTheDocument();
  });
});
