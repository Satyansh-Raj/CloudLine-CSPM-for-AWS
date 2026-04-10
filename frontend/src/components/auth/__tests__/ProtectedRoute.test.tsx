import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthContext } from "@/context/authContextValue";
import type { AuthContextValue, User } from "@/types/auth";
import { vi } from "vitest";
import ProtectedRoute from "../ProtectedRoute";

const TEST_USER: User = {
  sk: "u1",
  email: "admin@test.com",
  full_name: "Admin",
  role: "admin",
  is_active: true,
  last_login: null,
};

function makeAuth(
  overrides: Partial<AuthContextValue> = {},
): AuthContextValue {
  return {
    user: TEST_USER,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshMe: vi.fn(),
    ...overrides,
  };
}

function setup(
  auth: AuthContextValue,
  initialPath = "/protected",
) {
  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/login" element={<div>Login Page</div>} />
          <Route element={<ProtectedRoute />}>
            <Route
              path="/protected"
              element={<div>Protected Content</div>}
            />
          </Route>
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("ProtectedRoute", () => {
  it("renders children when user is authenticated", () => {
    setup(makeAuth({ user: TEST_USER }));
    expect(
      screen.getByText("Protected Content"),
    ).toBeInTheDocument();
  });

  it("redirects to /login when user is null", () => {
    setup(makeAuth({ user: null, isLoading: false }));
    expect(screen.getByText("Login Page")).toBeInTheDocument();
    expect(
      screen.queryByText("Protected Content"),
    ).not.toBeInTheDocument();
  });

  it("shows loading spinner while isLoading is true", () => {
    setup(
      makeAuth({ user: null, isLoading: true }),
    );
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(
      screen.queryByText("Protected Content"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Login Page"),
    ).not.toBeInTheDocument();
  });

  it("allows access when requireRole matches user role", () => {
    render(
      <AuthContext.Provider
        value={makeAuth({ user: { ...TEST_USER, role: "admin" } })}
      >
        <MemoryRouter initialEntries={["/protected"]}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route element={<ProtectedRoute requireRole="admin" />}>
              <Route
                path="/protected"
                element={<div>Admin Content</div>}
              />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>,
    );
    expect(screen.getByText("Admin Content")).toBeInTheDocument();
  });

  it("redirects when requireRole does not match", () => {
    render(
      <AuthContext.Provider
        value={makeAuth({ user: { ...TEST_USER, role: "viewer" } })}
      >
        <MemoryRouter initialEntries={["/protected"]}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route element={<ProtectedRoute requireRole="admin" />}>
              <Route
                path="/protected"
                element={<div>Admin Content</div>}
              />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>,
    );
    expect(
      screen.queryByText("Admin Content"),
    ).not.toBeInTheDocument();
  });
});
