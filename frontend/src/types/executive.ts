export interface DomainBreakdown {
  active: number;
  resolved: number;
  total_checks: number;
  score_percent: number;
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TrendData {
  resolved_last_24h: number;
  new_last_24h: number;
}

export interface ExecutiveSummary {
  total_active: number;
  total_resolved: number;
  resolution_rate: number;
  by_domain: Record<string, DomainBreakdown>;
  by_severity: SeverityBreakdown;
  trend: TrendData;
}
