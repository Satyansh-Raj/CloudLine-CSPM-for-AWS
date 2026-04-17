export type RiskCategory = "critical" | "high" | "medium" | "low";

export interface RiskScore {
  resource_arn: string;
  check_id: string;
  risk_score: number;
  category: RiskCategory;
  severity: string;
  domain: string;
  last_evaluated: string;
}

export interface RiskScoreParams {
  category?: RiskCategory;
  domain?: string;
  limit?: number;
  account_id?: string;
}

export interface RiskScoresResponse {
  scores: RiskScore[];
}

export interface RiskSummaryHighest {
  resource_arn: string;
  check_id: string;
  risk_score: number;
  severity: string;
  domain: string;
}

export interface RiskSummary {
  total_scored: number;
  by_category: Record<RiskCategory, number>;
  by_domain: Record<string, number>;
  highest_risk: RiskSummaryHighest[];
}
