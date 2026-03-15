export type WsEventType =
  | "violation_new"
  | "violation_resolved"
  | "no_change"
  | "first_seen"
  | "pong";

export interface WsEventData {
  check_id: string;
  resource_arn: string;
  previous_status: string | null;
  current_status: string;
  severity: string;
  risk_score: number;
  trigger_event: string;
  timestamp: string;
  reason: string;
  account_id: string;
  region: string;
}

export interface WsMessage {
  type: WsEventType;
  data?: WsEventData;
}

export type WsStatus =
  | "connecting"
  | "connected"
  | "disconnected";

export interface WsAlert {
  id: string;
  type: WsEventType;
  data: WsEventData;
  receivedAt: number;
  read: boolean;
}
