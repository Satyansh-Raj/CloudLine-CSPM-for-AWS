export type DriftType =
  | "new_violation"
  | "resolution"
  | "no_change"
  | "first_seen";

export interface DriftAlert {
  type: string;
  check_id: string;
  resource: string;
  severity: string;
  risk_score: number;
  timestamp: string;
  trigger_event: string;
  reason: string;
  domain: string;
  previous_status: string | null;
  current_status: string;
}

export interface DriftAlertParams {
  severity?: string;
  check_id?: string;
  limit?: number;
}

export interface DriftAlertsResponse {
  alerts: DriftAlert[];
}
