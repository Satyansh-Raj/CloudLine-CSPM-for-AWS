export { apiClient } from "./client";
export type { ApiError } from "./client";

export { getHealth } from "./health";
export { triggerScan } from "./scans";
export {
  getViolations,
  createJiraTicket,
  deleteJiraTicket,
  type ViolationParams,
} from "./violations";
export {
  getComplianceScore,
  getComplianceFrameworks,
  getFrameworkScore,
} from "./compliance";
export { getDriftAlerts } from "./drift";
export { getRiskScores, getRiskSummary } from "./risk";
export { createWsConnection, type WsConnectionOptions } from "./websocket";
export {
  getPolicies,
  createPolicy,
  deletePolicy,
  type PolicyInfo,
  type CreatePolicyRequest,
} from "./policies";
export { getIamGraph } from "./iamGraph";
export {
  getInventory,
  getInventorySummary,
  getInventoryDetail,
} from "./inventory";
export { getRegions, type RegionsResponse } from "./regions";
export { getExecutiveSummary, type ExecutiveSummaryParams } from "./executive";
