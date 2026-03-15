export interface DomainScore {
  total: number;
  passed: number;
  failed: number;
  score_percent: number;
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
}
