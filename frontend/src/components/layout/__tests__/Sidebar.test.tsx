import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

const mockSetSelectedAccount = vi.fn();
const mockRefresh = vi.fn();
const mockCreateAccount = vi.fn();

// Mock useAccount — Sidebar now has Account Popover
vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => ({
    selectedAccount: "111111111111",
    accounts: [
      {
        account_id: "111111111111",
        account_name: "Production",
        role_arn: "arn:aws:iam::111111111111:role/X",
        external_id: "",
        regions: ["ap-south-1"],
        is_active: true,
        added_at: "2026-03-18",
        last_scanned: null,
      },
      {
        account_id: "222222222222",
        account_name: "Staging",
        role_arn: "arn:aws:iam::222222222222:role/X",
        external_id: "",
        regions: ["us-east-1"],
        is_active: true,
        added_at: "2026-03-18",
        last_scanned: null,
      },
    ],
    isLoading: false,
    setSelectedAccount: mockSetSelectedAccount,
    refresh: mockRefresh,
  }),
}));

vi.mock("@/api/accounts", () => ({
  createAccount: (...args: unknown[]) =>
    mockCreateAccount(...args),
}));

import Sidebar from "../Sidebar";

function renderSidebar() {
  return render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>,
  );
}

describe("Sidebar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders CloudLine branding", () => {
    renderSidebar();
    expect(screen.getByText("CloudLine")).toBeInTheDocument();
    expect(screen.getByText("AWS Security")).toBeInTheDocument();
  });

  it("renders nav links", () => {
    renderSidebar();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Violations")).toBeInTheDocument();
    expect(screen.getByText("Trends")).toBeInTheDocument();
    expect(screen.getByText("Executive")).toBeInTheDocument();
  });

  it("does NOT show Accounts nav link", () => {
    renderSidebar();
    const links = screen.getAllByRole("link");
    const accountsLink = links.find(
      (l) => l.textContent?.includes("Accounts"),
    );
    expect(accountsLink).toBeUndefined();
  });

  it("shows version", () => {
    renderSidebar();
    expect(screen.getByText("v0.1.0")).toBeInTheDocument();
  });

  // Account switcher popover tests
  it("shows active account name in switcher button", () => {
    renderSidebar();
    expect(
      screen.getByText("Production"),
    ).toBeInTheDocument();
  });

  it("opens popover listing accounts on click", async () => {
    const user = userEvent.setup();
    renderSidebar();

    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);

    expect(
      screen.getByRole("listbox"),
    ).toBeInTheDocument();
    expect(screen.getByText("Staging")).toBeInTheDocument();
    expect(
      screen.getByText("222222222222"),
    ).toBeInTheDocument();
  });

  it("switches account when clicking another account", async () => {
    const user = userEvent.setup();
    renderSidebar();

    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);

    const stagingOption = screen
      .getByText("Staging")
      .closest("[role='option']")!;
    await user.click(stagingOption);

    expect(mockSetSelectedAccount).toHaveBeenCalledWith(
      "222222222222",
    );
  });

  it("shows All Accounts option in popover", async () => {
    const user = userEvent.setup();
    renderSidebar();

    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);

    expect(
      screen.getByText("All Accounts"),
    ).toBeInTheDocument();
  });

  it("shows Add Account button in popover", async () => {
    const user = userEvent.setup();
    renderSidebar();

    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);

    expect(
      screen.getByRole("button", {
        name: /add account/i,
      }),
    ).toBeInTheDocument();
  });

  it("opens Add Account modal with form fields", async () => {
    const user = userEvent.setup();
    renderSidebar();

    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);

    const addBtn = screen.getByRole("button", {
      name: /add account/i,
    });
    await user.click(addBtn);

    expect(
      screen.getByRole("dialog"),
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("Account Name"),
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("Account ID"),
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("Role ARN"),
    ).toBeInTheDocument();
  });

  it("submits Add Account form and refreshes", async () => {
    mockCreateAccount.mockResolvedValueOnce({
      account_id: "333333333333",
    });

    const user = userEvent.setup();
    renderSidebar();

    // Open popover
    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);

    // Open modal
    const addBtn = screen.getByRole("button", {
      name: /add account/i,
    });
    await user.click(addBtn);

    // Fill form
    await user.type(
      screen.getByPlaceholderText("Account Name"),
      "Dev",
    );
    await user.type(
      screen.getByPlaceholderText("Account ID"),
      "333333333333",
    );
    await user.type(
      screen.getByPlaceholderText("Role ARN"),
      "arn:aws:iam::333333333333:role/R",
    );

    // Submit
    const submitBtn = screen.getByRole("button", {
      name: /^save$/i,
    });
    await user.click(submitBtn);

    expect(mockCreateAccount).toHaveBeenCalledWith({
      account_name: "Dev",
      account_id: "333333333333",
      role_arn: "arn:aws:iam::333333333333:role/R",
    });
  });

  it("closes popover on outside click", async () => {
    const user = userEvent.setup();
    renderSidebar();

    const trigger = screen.getByRole("button", {
      name: /switch account/i,
    });
    await user.click(trigger);
    expect(screen.getByRole("listbox")).toBeInTheDocument();

    // Click outside
    await user.click(document.body);
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  });
});
