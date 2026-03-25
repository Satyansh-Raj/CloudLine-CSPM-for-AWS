import { apiClient } from "./client";
import type { ExecutiveSummary } from "@/types";

export interface ExecutiveSummaryParams {
  region?: string;
  account_id?: string;
}

export async function getExecutiveSummary(
  params?: ExecutiveSummaryParams,
): Promise<ExecutiveSummary> {
  const { data } = await apiClient.get<ExecutiveSummary>(
    "/v1/summary/executive",
    { params },
  );
  return data;
}
