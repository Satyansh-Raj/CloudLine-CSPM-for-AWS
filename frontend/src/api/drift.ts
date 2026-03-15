import { apiClient } from "./client";
import type {
  DriftAlertParams,
  DriftAlertsResponse,
} from "@/types";

export async function getDriftAlerts(
  params?: DriftAlertParams,
): Promise<DriftAlertsResponse> {
  const { data } = await apiClient.get<DriftAlertsResponse>(
    "/v1/drift/alerts",
    { params },
  );
  return data;
}
