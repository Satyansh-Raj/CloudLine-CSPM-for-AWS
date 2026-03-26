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
  iam_root_mfa: {
    cis_aws: ["1.5"],
    nist_800_53: ["IA-2(1)"],
    pci_dss: ["8.3.1"],
    soc2: ["CC6.1", "CC6.2"],
  },
  iam_pwd_min_length: {
    cis_aws: ["1.8", "1.9", "1.10", "1.11"],
    nist_800_53: ["IA-5"],
    soc2: ["CC6.1", "CC6.2"],
  },
  iam_user_mfa: {
    cis_aws: ["1.10"],
    nist_800_53: ["IA-2(1)"],
    pci_dss: ["8.3.1"],
    soc2: ["CC6.1", "CC6.2"],
  },
  s3_block_public_acls: {
    cis_aws: ["2.1.4"],
    nist_800_53: ["AC-3", "AC-4"],
    pci_dss: ["1.2.1"],
    soc2: ["CC6.1", "CC6.6"],
  },
  cloudtrail_enabled: {
    cis_aws: ["3.1", "3.2", "3.4"],
    nist_800_53: ["AU-2", "AU-3"],
    pci_dss: ["10.1"],
    soc2: ["CC7.2"],
  },
  vpc_flow_logs: {
    cis_aws: ["3.9"],
    nist_800_53: ["AU-12"],
    pci_dss: ["10.1"],
    soc2: ["CC6.6", "CC7.2"],
  },
  ec2_no_open_ssh: {
    cis_aws: ["5.2", "5.3"],
    nist_800_53: ["AC-4", "SC-7"],
    pci_dss: ["1.3.1"],
    soc2: ["CC6.1", "CC6.6"],
  },
  ec2_imdsv2: {
    cis_aws: ["5.6"],
    nist_800_53: ["AC-4"],
    soc2: ["CC6.1"],
  },
  db_rds_no_public_access: {
    cis_aws: ["2.3"],
    nist_800_53: ["SC-7", "SC-28", "CP-9"],
    pci_dss: ["1.3.1", "3.4"],
    soc2: ["CC6.1", "CC6.6"],
  },
  iam_inactive_user: {
    cis_aws: ["1.12"],
    nist_800_53: ["AC-2(3)"],
    soc2: ["CC6.1", "CC6.2"],
  },
  s3_encryption: {
    nist_800_53: ["SC-8"],
    pci_dss: ["4.1"],
    soc2: ["CC6.8", "C1.1"],
  },
  config_recorder_enabled: {
    cis_aws: ["3.5"],
    nist_800_53: ["CM-3"],
    soc2: ["CC7.1", "CC7.2"],
  },
  awssec_guardduty_enabled: {
    cis_aws: ["4.15"],
    nist_800_53: ["SI-4"],
    soc2: ["CC7.1", "CC7.2"],
  },
  serverless_lambda_xray: {
    nist_800_53: ["AC-6", "SC-28"],
    soc2: ["CC7.2"],
  },
  vpc_nacl_no_all_inbound: {
    nist_800_53: ["AC-4", "SC-7"],
    soc2: ["CC6.1", "CC6.6"],
  },
  secretsmanager_auto_rotation: {
    cis_aws: ["2.4"],
    nist_800_53: ["IA-5"],
    soc2: ["CC6.2", "CC6.7"],
  },
  storage_ebs_encryption: {
    cis_aws: ["2.2.1"],
    nist_800_53: ["SC-28"],
    pci_dss: ["3.4"],
    hipaa: ["164.312(a)(2)(iv)"],
    soc2: ["CC6.8", "C1.1"],
  },
  cloudwatch_root_usage_alarm: {
    cis_aws: ["4.1"],
    nist_800_53: ["AU-6"],
    soc2: ["CC7.2", "CC7.3", "CC7.4"],
  },
  iam_access_analyzer: {
    cis_aws: ["1.20"],
    nist_800_53: ["AC-6"],
    soc2: ["CC6.1", "CC7.1"],
  },
  backup_01: {
    nist_800_53: ["CP-9"],
    hipaa: ["164.308(a)(7)"],
    soc2: ["A1.2"],
  },
  cross_capital_one_pattern: {
    cis_aws: ["1.16", "5.2"],
    nist_800_53: ["AC-6", "AC-4"],
    soc2: ["CC6.1", "CC6.3"],
  },
};

export function getComplianceMapping(checkId: string): ComplianceMapping {
  return COMPLIANCE_MAP[checkId] ?? {};
}
