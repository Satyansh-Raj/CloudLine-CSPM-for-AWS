import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import type { RenderOptions } from "@testing-library/react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AlertProvider } from "@/context/AlertContext";
import { AuthContext } from "@/context/authContextValue";
import type { AuthContextValue, User } from "@/types/auth";

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface WrapperOptions {
  route?: string;
}

function createWrapper(opts: WrapperOptions = {}) {
  const { route = "/" } = opts;

  const qc = createTestQueryClient();

  return function Wrapper({
    children,
  }: {
    children: ReactNode;
  }) {
    return (
      <QueryClientProvider client={qc}>
        <AlertProvider>
          <MemoryRouter initialEntries={[route]}>
            {children}
          </MemoryRouter>
        </AlertProvider>
      </QueryClientProvider>
    );
  };
}

export function renderWithProviders(
  ui: React.ReactElement,
  opts: WrapperOptions & RenderOptions = {},
) {
  const { route, ...renderOpts } = opts;
  const Wrapper = createWrapper({ route });
  return render(ui, {
    wrapper: Wrapper,
    ...renderOpts,
  });
}

// ── Auth-aware render helper ──────────────────────

/** Default Admin user injected by renderWithAuth. */
export const TEST_ADMIN_USER: User = {
  sk: "test-admin",
  email: "admin@test.com",
  full_name: "Test Admin",
  role: "admin",
  is_active: true,
  last_login: null,
};

interface AuthWrapperOptions extends WrapperOptions {
  /** Override the injected user (null = logged out). */
  user?: User | null;
}

/**
 * Render with a mock AuthProvider.
 *
 * Default user is TEST_ADMIN_USER so existing
 * tests relying on admin access keep passing when
 * components add RoleGate checks in Batch 4F/4G.
 */
export function renderWithAuth(
  ui: React.ReactElement,
  opts: AuthWrapperOptions & RenderOptions = {},
) {
  const {
    route = "/",
    user = TEST_ADMIN_USER,
    ...renderOpts
  } = opts;

  const mockAuth: AuthContextValue = {
    user,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshMe: vi.fn(),
  };

  const qc = createTestQueryClient();

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={qc}>
        <AlertProvider>
          <AuthContext.Provider value={mockAuth}>
            <MemoryRouter initialEntries={[route]}>
              {children}
            </MemoryRouter>
          </AuthContext.Provider>
        </AlertProvider>
      </QueryClientProvider>
    );
  }

  return render(ui, { wrapper: Wrapper, ...renderOpts });
}

export { createTestQueryClient };
