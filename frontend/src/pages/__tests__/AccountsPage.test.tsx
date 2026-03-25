import {
  render,
  screen,
  fireEvent,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AccountsPage from "../AccountsPage";

const mockAccounts = [
  {
    account_id: "111111111111",
    account_name: "Production",
    role_arn:
      "arn:aws:iam::111111111111:role/CloudLineScanner",
    external_id: "",
    regions: ["us-east-1"],
    is_active: true,
    added_at: "2026-03-18T10:00:00Z",
    last_scanned: "2026-03-18T11:00:00Z",
  },
  {
    account_id: "222222222222",
    account_name: "Staging",
    role_arn:
      "arn:aws:iam::222222222222:role/CloudLineScanner",
    external_id: "ext-123",
    regions: ["eu-west-1"],
    is_active: true,
    added_at: "2026-03-17T08:00:00Z",
    last_scanned: null,
  },
];

const mockContext = {
  selectedAccount: "",
  accounts: mockAccounts,
  isLoading: false,
  setSelectedAccount: vi.fn(),
  refresh: vi.fn(),
};

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => mockContext,
}));

vi.mock("@/api/accounts", () => ({
  getAccounts: vi.fn(),
  createAccount: vi.fn().mockResolvedValue({
    account_id: "333333333333",
    account_name: "Dev",
  }),
  deleteAccount: vi.fn().mockResolvedValue(undefined),
}));

import {
  createAccount,
  deleteAccount,
} from "@/api/accounts";

function renderPage() {
  return render(
    <MemoryRouter>
      <AccountsPage />
    </MemoryRouter>,
  );
}

describe("AccountsPage", () => {
  afterEach(() => {
    mockContext.accounts = mockAccounts;
    mockContext.isLoading = false;
    vi.clearAllMocks();
  });

  it("shows page heading", () => {
    renderPage();
    expect(
      screen.getByText("Accounts"),
    ).toBeInTheDocument();
  });

  it("lists existing accounts", () => {
    renderPage();
    expect(
      screen.getByText("Production"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Staging"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("111111111111"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("222222222222"),
    ).toBeInTheDocument();
  });

  it("shows role ARN for each account", () => {
    renderPage();
    expect(
      screen.getByText(
        /arn:aws:iam::111111111111:role/,
      ),
    ).toBeInTheDocument();
  });

  it("shows last scanned status", () => {
    renderPage();
    // Production was scanned, Staging was not
    expect(
      screen.getByText(/never/i),
    ).toBeInTheDocument();
  });

  it("shows add account form", () => {
    renderPage();
    expect(
      screen.getByPlaceholderText(/account name/i),
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/account id/i),
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/role arn/i),
    ).toBeInTheDocument();
  });

  it("calls createAccount on form submit",
    async () => {
      renderPage();

      fireEvent.change(
        screen.getByPlaceholderText(/account name/i),
        { target: { value: "Dev" } },
      );
      fireEvent.change(
        screen.getByPlaceholderText(/account id/i),
        { target: { value: "333333333333" } },
      );
      fireEvent.change(
        screen.getByPlaceholderText(/role arn/i),
        {
          target: {
            value: "arn:aws:iam::333333333333:role/Scanner",
          },
        },
      );

      fireEvent.click(
        screen.getByRole("button", {
          name: /add account/i,
        }),
      );

      await waitFor(() => {
        expect(createAccount).toHaveBeenCalledWith(
          expect.objectContaining({
            account_id: "333333333333",
            account_name: "Dev",
            role_arn:
              "arn:aws:iam::333333333333:role/Scanner",
          }),
        );
      });
    });

  it("calls deleteAccount when remove is clicked",
    async () => {
      renderPage();

      const removeButtons = screen.getAllByRole(
        "button",
        { name: /remove/i },
      );
      fireEvent.click(removeButtons[0]);

      await waitFor(() => {
        expect(
          deleteAccount,
        ).toHaveBeenCalledWith("111111111111");
      });
    });

  it("calls refresh after add/delete", async () => {
    renderPage();

    fireEvent.change(
      screen.getByPlaceholderText(/account name/i),
      { target: { value: "Dev" } },
    );
    fireEvent.change(
      screen.getByPlaceholderText(/account id/i),
      { target: { value: "333333333333" } },
    );
    fireEvent.change(
      screen.getByPlaceholderText(/role arn/i),
      {
        target: {
          value: "arn:aws:iam::333333333333:role/S",
        },
      },
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: /add account/i,
      }),
    );

    await waitFor(() => {
      expect(
        mockContext.refresh,
      ).toHaveBeenCalled();
    });
  });

  it("shows empty state when no accounts", () => {
    mockContext.accounts = [];
    renderPage();
    expect(
      screen.getByText(
        /no target accounts configured/i,
      ),
    ).toBeInTheDocument();
  });

  it("shows regions for each account", () => {
    renderPage();
    expect(
      screen.getByText("us-east-1"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("eu-west-1"),
    ).toBeInTheDocument();
  });
});
