import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AlertProvider } from "@/context/AlertContext";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";

// Mock useWebSocket to avoid real WS connections
vi.mock("@/hooks/useWebSocket", () => ({
  useWebSocket: () => {},
}));

import Layout from "../Layout";

function Wrapper({
  children,
}: {
  children: ReactNode;
}) {
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
    expect(
      screen.getByText("CloudLine"),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText("Toggle dark mode"),
    ).toBeInTheDocument();
  });

  it("renders nav links", () => {
    render(
      <Wrapper>
        <Layout />
      </Wrapper>,
    );
    expect(
      screen.getByText("Dashboard"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Violations"),
    ).toBeInTheDocument();
  });
});
