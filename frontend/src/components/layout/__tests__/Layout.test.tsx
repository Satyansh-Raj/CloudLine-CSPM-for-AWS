import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AlertProvider } from "@/context/AlertContext";
import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Mock useWebSocket to avoid real WS connections
vi.mock("@/hooks/useWebSocket", () => ({
  useWebSocket: () => {},
}));

// Mock useAccount — Sidebar uses AccountSelector
vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "",
    accounts: [],
    isLoading: false,
    setSelectedAccount: vi.fn(),
    refresh: vi.fn(),
  }),
}));

// Mock usePermission — Sidebar conditionally renders User Management link
vi.mock("@/hooks/usePermission", () => ({
  usePermission: () => ({
    role: "viewer",
    can: () => false,
  }),
}));

// Mock useAuth — Header now renders user menu
vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => ({
    user: null,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshMe: vi.fn(),
  }),
}));

import Layout from "../Layout";

function Wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  return (
    <QueryClientProvider client={qc}>
      <AlertProvider>
        <MemoryRouter>{children}</MemoryRouter>
      </AlertProvider>
    </QueryClientProvider>
  );
}

describe("Layout", () => {
  it("renders sidebar and header", () => {
    render(
      <Wrapper>
        <Layout />
      </Wrapper>,
    );
    expect(screen.getByText("CloudLine")).toBeInTheDocument();
    expect(screen.getByLabelText("Toggle dark mode")).toBeInTheDocument();
  });

  it("renders nav links", () => {
    render(
      <Wrapper>
        <Layout />
      </Wrapper>,
    );
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Violations")).toBeInTheDocument();
  });
});
