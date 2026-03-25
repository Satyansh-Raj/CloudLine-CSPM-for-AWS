export type Severity = "critical" | "high" | "medium" | "low";

export type ViolationStatus = "alarm" | "ok" | "error" | "skip";

export interface ComplianceMapping {
  cis_aws: string[];
  nist_800_53: string[];
  pci_dss: string[];
  hipaa: string[];
  soc2: string[];
}

export interface Violation {
  check_id: string;
  status: ViolationStatus;
  severity: Severity;
  reason: string;
  resource: string;
  domain: string;
  compliance: ComplianceMapping;
  remediation_id: string;
  risk_score?: number;
  last_evaluated?: string;
  first_detected?: string;
  resolved_at?: string;
  previous_status?: string;
  ticket_id?: string;
  ticket_url?: string;
  account_id?: string;
  region?: string;
  status_history?: StatusHistoryEntry[];
  regression_count?: number;
}

export interface StatusHistoryEntry {
  status: string;
  timestamp: string;
}

export interface JiraTicketResponse {
  ticket_id: string;
  ticket_url: string;
  ticket_key: string;
}

export interface CreateTicketParams {
  account_id: string;
  region: string;
  check_id: string;
  resource_id: string;
  summary?: string;
  priority?: string;
  labels?: string[];
}
