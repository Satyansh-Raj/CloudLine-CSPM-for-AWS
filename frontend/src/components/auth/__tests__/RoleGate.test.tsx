import { render, screen } from "@testing-library/react";
import { vi } from "vitest";
import { AuthContext } from "@/context/authContextValue";
import type { AuthContextValue, User } from "@/types/auth";
import { MemoryRouter } from "react-router-dom";
import RoleGate from "../RoleGate";

const makeUser = (role: User["role"]): User => ({
  sk: "u1",
  email: "user@test.com",
  full_name: "User",
  role,
  is_active: true,
  last_login: null,
});

function makeAuth(user: User | null): AuthContextValue {
  return {
    user,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshMe: vi.fn(),
  };
}

function setup(
  auth: AuthContextValue,
  allow: User["role"][],
  fallback?: React.ReactNode,
) {
  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter>
        <RoleGate allow={allow} fallback={fallback}>
          <div>Gated Content</div>
        </RoleGate>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("RoleGate", () => {
  it("renders children when user role is in allow list", () => {
    setup(makeAuth(makeUser("admin")), ["admin"]);
    expect(
      screen.getByText("Gated Content"),
    ).toBeInTheDocument();
  });

  it("renders children when user is operator and operator is allowed", () => {
    setup(
      makeAuth(makeUser("operator")),
      ["admin", "operator"],
    );
    expect(
      screen.getByText("Gated Content"),
    ).toBeInTheDocument();
  });

  it("renders nothing when role is not in allow list", () => {
    setup(makeAuth(makeUser("viewer")), ["admin"]);
    expect(
      screen.queryByText("Gated Content"),
    ).not.toBeInTheDocument();
  });

  it("renders fallback when role is not in allow list", () => {
    setup(
      makeAuth(makeUser("viewer")),
      ["admin"],
      <div>No Access</div>,
    );
    expect(
      screen.queryByText("Gated Content"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("No Access")).toBeInTheDocument();
  });

  it("renders nothing when user is null", () => {
    setup(makeAuth(null), ["admin"]);
    expect(
      screen.queryByText("Gated Content"),
    ).not.toBeInTheDocument();
  });

  it("renders children for viewer when viewer is in allow list", () => {
    setup(
      makeAuth(makeUser("viewer")),
      ["admin", "operator", "viewer"],
    );
    expect(
      screen.getByText("Gated Content"),
    ).toBeInTheDocument();
  });
});
