import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AlertProvider } from "@/context/AlertContext";
import Header from "../Header";

const mockLogout = vi.fn();
const mockNavigate = vi.fn();

vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => ({
    user: {
      sk: "u1",
      email: "admin@test.com",
      full_name: "Admin User",
      role: "admin",
      is_active: true,
      last_login: null,
    },
    isLoading: false,
    login: vi.fn(),
    logout: mockLogout,
    refreshMe: vi.fn(),
  }),
}));

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

  it("shows user email and role pill", () => {
    renderHeader();
    expect(screen.getByText("admin@test.com")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  it("opens user menu on click", async () => {
    const user = userEvent.setup();
    renderHeader();
    await user.click(screen.getByRole("button", { name: /user menu/i }));
    expect(screen.getByText("Change Password")).toBeInTheDocument();
    expect(screen.getByText("Sign Out")).toBeInTheDocument();
  });

  it("calls logout and navigates on Sign Out", async () => {
    const user = userEvent.setup();
    renderHeader();
    await user.click(screen.getByRole("button", { name: /user menu/i }));
    await user.click(screen.getByText("Sign Out"));
    expect(mockLogout).toHaveBeenCalled();
    expect(mockNavigate).toHaveBeenCalledWith("/login");
  });
});
