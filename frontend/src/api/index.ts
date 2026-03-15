export { apiClient } from "./client";
export type { ApiError } from "./client";

export { getHealth } from "./health";
export { triggerScan } from "./scans";
export {
  getViolations,
  type ViolationParams,
} from "./violations";
export { getComplianceScore } from "./compliance";
export { getDriftAlerts } from "./drift";
export { getRiskScores, getRiskSummary } from "./risk";
export {
  createWsConnection,
  type WsConnectionOptions,
} from "./websocket";
export {
  getPolicies,
  createPolicy,
  deletePolicy,
  type PolicyInfo,
  type CreatePolicyRequest,
} from "./policies";
export { getIamGraph } from "./iamGraph";
