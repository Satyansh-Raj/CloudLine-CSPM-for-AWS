import {
  render,
  screen,
  fireEvent,
} from "@testing-library/react";
import AccountSelector from "../AccountSelector";

const mockAccount = {
  selectedAccount: "",
  accounts: [
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
    {
      account_id: "222222222222",
      account_name: "Staging",
      role_arn: "arn:role",
      external_id: "",
      regions: ["eu-west-1"],
      is_active: true,
      added_at: "2026-03-18T10:00:00Z",
      last_scanned: null,
    },
  ],
  isLoading: false,
  setSelectedAccount: vi.fn(),
  refresh: vi.fn(),
};

vi.mock("@/hooks/useAccount", () => ({
  useAccount: () => mockAccount,
}));

describe("AccountSelector", () => {
  afterEach(() => {
    mockAccount.selectedAccount = "";
    vi.clearAllMocks();
  });

  it("renders a select dropdown", () => {
    render(<AccountSelector />);
    expect(
      screen.getByLabelText("Select account"),
    ).toBeInTheDocument();
  });

  it("shows All Accounts option", () => {
    render(<AccountSelector />);
    expect(
      screen.getByText("All Accounts"),
    ).toBeInTheDocument();
  });

  it("lists account names with IDs", () => {
    render(<AccountSelector />);
    expect(
      screen.getByText(/Production/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Staging/),
    ).toBeInTheDocument();
  });

  it("calls setSelectedAccount on change", () => {
    render(<AccountSelector />);
    const select = screen.getByLabelText(
      "Select account",
    );
    fireEvent.change(select, {
      target: { value: "111111111111" },
    });
    expect(
      mockAccount.setSelectedAccount,
    ).toHaveBeenCalledWith("111111111111");
  });

  it("shows current selection", () => {
    mockAccount.selectedAccount = "222222222222";
    render(<AccountSelector />);
    const select = screen.getByLabelText(
      "Select account",
    ) as HTMLSelectElement;
    expect(select.value).toBe("222222222222");
  });
});
