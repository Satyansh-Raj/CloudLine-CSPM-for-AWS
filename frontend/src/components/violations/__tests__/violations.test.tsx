import {
  render,
  screen,
  act,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ViolationsTable from "../ViolationsTable";
import ViolationFilters from "../ViolationFilters";

const mockViolations = [
  {
    check_id: "s3_block_public_acls",
    resource: "arn:aws:s3:::bucket-1",
    severity: "critical",
    status: "alarm",
    domain: "data_protection",
    reason: "Public access",
    remediation_id: "REM_s3_01",
    compliance: {
      cis_aws: ["2.1.5"],
      nist_800_53: ["AC-3"],
      pci_dss: ["1.3.1"],
      hipaa: [],
      soc2: [],
    },
  },
  {
    check_id: "ec2_no_open_ssh",
    resource: "arn:aws:ec2:::i-123",
    severity: "critical",
    status: "alarm",
    domain: "compute",
    reason: "Open SSH port",
    remediation_id: "REM_ec2_05",
    compliance: {
      cis_aws: ["5.2"],
      nist_800_53: ["SC-7"],
      pci_dss: [],
      hipaa: [],
      soc2: [],
    },
  },
];

describe("ViolationsTable", () => {
  it("renders table with violations", () => {
    render(
      <ViolationsTable
        data={mockViolations}
        onRowClick={() => {}}
      />,
    );
    expect(
      screen.getByText("s3_block_public_acls"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("ec2_no_open_ssh"),
    ).toBeInTheDocument();
  });

  it("renders empty state", () => {
    render(
      <ViolationsTable
        data={[]}
        onRowClick={() => {}}
      />,
    );
    expect(
      screen.getByText("No violations found."),
    ).toBeInTheDocument();
  });

  it("calls onRowClick", async () => {
    const onClick = vi.fn();
    const user = userEvent.setup();
    render(
      <ViolationsTable
        data={mockViolations}
        onRowClick={onClick}
      />,
    );

    await user.click(screen.getByText("s3_block_public_acls"));
    expect(onClick).toHaveBeenCalledWith(
      mockViolations[0],
    );
  });

  it("renders column headers", () => {
    render(
      <ViolationsTable
        data={mockViolations}
        onRowClick={() => {}}
      />,
    );
    expect(
      screen.getByText("Issue"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Severity"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Status"),
    ).toBeInTheDocument();
  });
});

describe("ViolationFilters", () => {
  it("renders filter dropdowns", () => {
    render(
      <ViolationFilters
        filters={{ severity: "", domain: "" }}
        onChange={() => {}}
      />,
    );
    const selects = screen.getAllByRole("combobox");
    expect(selects.length).toBeGreaterThanOrEqual(2);
  });

  it("calls onChange on filter change", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(
      <ViolationFilters
        filters={{ severity: "", domain: "" }}
        onChange={onChange}
      />,
    );

    const selects = screen.getAllByRole("combobox");
    await user.selectOptions(selects[0], "critical");
    expect(onChange).toHaveBeenCalled();
  });

  it("shows clear button when filter active", () => {
    render(
      <ViolationFilters
        filters={{ severity: "critical", domain: "" }}
        onChange={() => {}}
      />,
    );
    expect(
      screen.getByText("Clear filters"),
    ).toBeInTheDocument();
  });
});
