/**
 * Static compliance framework mappings for each check.
 * Sourced from the Rego policy metadata.
 */
export interface ComplianceMapping {
  cis_aws?: string[];
  nist_800_53?: string[];
  pci_dss?: string[];
  hipaa?: string[];
  soc2?: string[];
}

const COMPLIANCE_MAP: Record<string, ComplianceMapping> = {
  iam_01: {
    cis_aws: ["1.5"],
    nist_800_53: ["IA-2(1)"],
    pci_dss: ["8.3.1"],
  },
  iam_02: {
    cis_aws: ["1.8", "1.9", "1.10", "1.11"],
    nist_800_53: ["IA-5"],
  },
  iam_09: {
    cis_aws: ["1.10"],
    nist_800_53: ["IA-2(1)"],
    pci_dss: ["8.3.1"],
  },
  s3_01: {
    cis_aws: ["2.1.4"],
    nist_800_53: ["AC-3", "AC-4"],
    pci_dss: ["1.2.1"],
  },
  cloudtrail_01: {
    cis_aws: ["3.1", "3.2", "3.4"],
    nist_800_53: ["AU-2", "AU-3"],
    pci_dss: ["10.1"],
  },
  vpc_01: {
    cis_aws: ["3.9"],
    nist_800_53: ["AU-12"],
    pci_dss: ["10.1"],
  },
  ec2_05: {
    cis_aws: ["5.2", "5.3"],
    nist_800_53: ["AC-4", "SC-7"],
    pci_dss: ["1.3.1"],
  },
  ec2_01: {
    cis_aws: ["5.6"],
    nist_800_53: ["AC-4"],
  },
  db_01: {
    cis_aws: ["2.3"],
    nist_800_53: ["SC-7", "SC-28", "CP-9"],
    pci_dss: ["1.3.1", "3.4"],
  },
  iam_14: {
    cis_aws: ["1.12"],
    nist_800_53: ["AC-2(3)"],
  },
  s3_05: {
    nist_800_53: ["SC-8"],
    pci_dss: ["4.1"],
  },
  config_01: {
    cis_aws: ["3.5"],
    nist_800_53: ["CM-3"],
  },
  awssec_01: {
    cis_aws: ["4.15"],
    nist_800_53: ["SI-4"],
  },
  serverless_01: {
    nist_800_53: ["AC-6", "SC-28"],
  },
  vpc_05: {
    nist_800_53: ["AC-4", "SC-7"],
  },
  secretsmanager_01: {
    cis_aws: ["2.4"],
    nist_800_53: ["IA-5"],
  },
  storage_01: {
    cis_aws: ["2.2.1"],
    nist_800_53: ["SC-28"],
    pci_dss: ["3.4"],
    hipaa: ["164.312(a)(2)(iv)"],
  },
  cloudwatch_01: {
    cis_aws: ["4.1"],
    nist_800_53: ["AU-6"],
  },
  iam_15: {
    cis_aws: ["1.20"],
    nist_800_53: ["AC-6"],
  },
  backup_01: {
    nist_800_53: ["CP-9"],
    hipaa: ["164.308(a)(7)"],
  },
  CROSS_01: {
    cis_aws: ["1.16", "5.2"],
    nist_800_53: ["AC-6", "AC-4"],
  },
};

export function getComplianceMapping(
  checkId: string,
): ComplianceMapping {
  return COMPLIANCE_MAP[checkId] ?? {};
}
