import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AlertProvider } from "@/context/AlertContext";
import Header from "../Header";

function renderHeader() {
  return render(
    <MemoryRouter>
      <AlertProvider>
        <Header />
      </AlertProvider>
    </MemoryRouter>,
  );
}

describe("Header", () => {
  it("renders dark mode toggle", () => {
    renderHeader();
    expect(screen.getByLabelText("Toggle dark mode")).toBeInTheDocument();
  });

  it("renders notification bell", () => {
    renderHeader();
    expect(screen.getByLabelText("Notifications")).toBeInTheDocument();
  });

  it("shows ws status", () => {
    renderHeader();
    expect(screen.getByText("Offline")).toBeInTheDocument();
  });

  it("toggles dark mode", async () => {
    const user = userEvent.setup();
    renderHeader();

    await user.click(screen.getByLabelText("Toggle dark mode"));
    expect(document.documentElement.classList.contains("dark")).toBe(true);

    await user.click(screen.getByLabelText("Toggle dark mode"));
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("toggles notification feed", async () => {
    const user = userEvent.setup();
    renderHeader();

    await user.click(screen.getByLabelText("Notifications"));
    expect(screen.getByText("Live Alerts")).toBeInTheDocument();
  });
});
