import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import type { RenderOptions } from "@testing-library/react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AlertProvider } from "@/context/AlertContext";

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
  return render(ui, { wrapper: Wrapper, ...renderOpts });
}

export { createTestQueryClient };
