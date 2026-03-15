import { apiClient } from "./client";
import type { ComplianceScore } from "@/types";

export async function getComplianceScore(): Promise<ComplianceScore> {
  const { data } = await apiClient.get<ComplianceScore>(
    "/v1/compliance/score",
  );
  return data;
}
