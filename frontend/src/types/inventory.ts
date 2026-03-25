export type Exposure = "internet" | "private" | "unknown";

export interface Resource {
  resource_id: string;
  resource_name: string;
  resource_type: string;
  technology_category: string;
  service: string;
  region: string;
  account_id: string;
  exposure: Exposure;
  environment: string;
  owner: string;
  tags: Record<string, string>;
  is_active: boolean;
  created_at: string | null;
  last_seen: string;
  violation_count: number;
  critical_violations: number;
  high_violations: number;
  risk_score: number;
  connected_to: string[];
  managed_by: string | null;
  belongs_to: string | null;
}

export interface InventorySummary {
  total: number;
  by_category: Record<string, number>;
  by_exposure: Record<string, number>;
  by_service: Record<string, number>;
}

export interface InventoryParams {
  category?: string;
  exposure?: string;
  service?: string;
  search?: string;
  limit?: number;
  region?: string;
  account_id?: string;
}
