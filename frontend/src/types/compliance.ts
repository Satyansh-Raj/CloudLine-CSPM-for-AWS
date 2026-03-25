export interface DomainScore {
  total: number;
  passed: number;
  failed: number;
  score_percent: number;
}

export interface FrameworkSummary {
  score_percent: number;
  total_controls: number;
  compliant: number;
  non_compliant: number;
}

export interface ControlViolation {
  resource_arn: string;
  severity: string;
  reason: string;
}

export interface ControlStatus {
  control_id: string;
  status: "compliant" | "non_compliant";
  check_ids: string[];
  violations: ControlViolation[];
  severity: string;
}

export interface FrameworkScore {
  framework: string;
  total_controls: number;
  compliant: number;
  non_compliant: number;
  score_percent: number;
  controls: ControlStatus[];
}

export interface ComplianceScore {
  total_checks: number;
  passed: number;
  failed: number;
  total_violations: number;
  errors: number;
  skipped: number;
  score_percent: number;
  by_domain: Record<string, DomainScore>;
  by_severity: Record<string, number>;
  by_framework?: Record<string, FrameworkSummary>;
}
