import { apiClient } from "./client";
import type { ComplianceScore, FrameworkScore } from "@/types";

export async function getComplianceScore(
  accountId?: string,
): Promise<ComplianceScore> {
  const { data } = await apiClient.get<ComplianceScore>(
    "/v1/compliance/score",
    {
      params: accountId ? { account_id: accountId } : undefined,
    },
  );
  return data;
}

export async function getComplianceFrameworks(): Promise<{
  frameworks: string[];
}> {
  const { data } = await apiClient.get<{ frameworks: string[] }>(
    "/v1/compliance/frameworks",
  );
  return data;
}

interface FrameworkParams {
  region?: string;
  account_id?: string;
}

export async function getFrameworkScore(
  framework: string,
  params?: FrameworkParams,
): Promise<FrameworkScore> {
  const { data } = await apiClient.get<FrameworkScore>(
    `/v1/compliance/framework/${framework}`,
    { params },
  );
  return data;
}
