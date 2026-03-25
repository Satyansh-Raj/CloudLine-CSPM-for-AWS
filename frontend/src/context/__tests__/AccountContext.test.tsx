import {
  render,
  screen,
  act,
  waitFor,
} from "@testing-library/react";
import { AccountProvider } from "../AccountContext";
import { useAccount } from "@/hooks/useAccount";

// --- mock getAccounts API ---
vi.mock("@/api/accounts", () => ({
  getAccounts: vi.fn(),
  createAccount: vi.fn(),
  deleteAccount: vi.fn(),
}));

import { getAccounts } from "@/api/accounts";
const mockGetAccounts =
  getAccounts as ReturnType<typeof vi.fn>;

// --- consumer component ---
function AccountConsumer() {
  const ctx = useAccount();
  return (
    <div>
      <span data-testid="selected">
        {ctx.selectedAccount}
      </span>
      <span data-testid="accounts">
        {ctx.accounts
          .map((a) => a.account_id)
          .join(",")}
      </span>
      <span data-testid="loading">
        {String(ctx.isLoading)}
      </span>
      <button
        onClick={() =>
          ctx.setSelectedAccount("111111111111")
        }
      >
        select
      </button>
      <button onClick={() => ctx.refresh()}>
        refresh
      </button>
    </div>
  );
}

function renderProvider() {
  return render(
    <AccountProvider>
      <AccountConsumer />
    </AccountProvider>,
  );
}

describe("AccountContext", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders children", () => {
    mockGetAccounts.mockResolvedValue([]);
    renderProvider();
    expect(
      screen.getByTestId("selected"),
    ).toBeInTheDocument();
  });

  it("provides default selectedAccount as empty string",
    async () => {
      mockGetAccounts.mockResolvedValue([]);
      renderProvider();
      expect(
        screen.getByTestId("selected"),
      ).toHaveTextContent("");
    });

  it("provides accounts from API", async () => {
    mockGetAccounts.mockResolvedValue([
      {
        account_id: "111111111111",
        account_name: "Production",
        role_arn: "arn:aws:iam::111111111111:role/Scanner",
        external_id: "",
        regions: ["us-east-1"],
        is_active: true,
        added_at: "2026-03-18T10:00:00Z",
        last_scanned: null,
      },
      {
        account_id: "222222222222",
        account_name: "Staging",
        role_arn: "arn:aws:iam::222222222222:role/Scanner",
        external_id: "",
        regions: ["eu-west-1"],
        is_active: true,
        added_at: "2026-03-18T10:00:00Z",
        last_scanned: null,
      },
    ]);
    renderProvider();
    await waitFor(() => {
      expect(
        screen.getByTestId("accounts"),
      ).toHaveTextContent(
        "111111111111,222222222222",
      );
    });
  });

  it("setSelectedAccount updates the value",
    async () => {
      mockGetAccounts.mockResolvedValue([
        {
          account_id: "111111111111",
          account_name: "Production",
          role_arn: "arn:role",
          external_id: "",
          regions: ["us-east-1"],
          is_active: true,
          added_at: "2026-03-18T10:00:00Z",
          last_scanned: null,
        },
      ]);
      renderProvider();

      await act(async () => {
        screen.getByText("select").click();
      });

      expect(
        screen.getByTestId("selected"),
      ).toHaveTextContent("111111111111");
    });

  it("provides isLoading state", async () => {
    mockGetAccounts.mockReturnValue(
      new Promise(() => {}),
    );
    renderProvider();
    expect(
      screen.getByTestId("loading"),
    ).toHaveTextContent("true");
  });

  it("isLoading becomes false after fetch",
    async () => {
      mockGetAccounts.mockResolvedValue([]);
      renderProvider();
      await waitFor(() => {
        expect(
          screen.getByTestId("loading"),
        ).toHaveTextContent("false");
      });
    });

  it("handles fetch error gracefully", async () => {
    mockGetAccounts.mockRejectedValue(
      new Error("Network error"),
    );
    renderProvider();
    await waitFor(() => {
      expect(
        screen.getByTestId("loading"),
      ).toHaveTextContent("false");
    });
    expect(
      screen.getByTestId("accounts"),
    ).toHaveTextContent("");
  });

  it("refresh re-fetches accounts", async () => {
    mockGetAccounts.mockResolvedValue([]);
    renderProvider();
    await waitFor(() => {
      expect(
        screen.getByTestId("loading"),
      ).toHaveTextContent("false");
    });

    mockGetAccounts.mockResolvedValue([
      {
        account_id: "333333333333",
        account_name: "Dev",
        role_arn: "arn:role",
        external_id: "",
        regions: ["us-east-1"],
        is_active: true,
        added_at: "2026-03-18T10:00:00Z",
        last_scanned: null,
      },
    ]);

    await act(async () => {
      screen.getByText("refresh").click();
    });

    await waitFor(() => {
      expect(
        screen.getByTestId("accounts"),
      ).toHaveTextContent("333333333333");
    });
  });
});
