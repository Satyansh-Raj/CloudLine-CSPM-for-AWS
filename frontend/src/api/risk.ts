import { apiClient } from "./client";
import type {
  RiskScoreParams,
  RiskScoresResponse,
  RiskSummary,
} from "@/types";

export async function getRiskScores(
  params?: RiskScoreParams,
): Promise<RiskScoresResponse> {
  const { data } =
    await apiClient.get<RiskScoresResponse>(
      "/v1/risk/scores",
      { params },
    );
  return data;
}

export async function getRiskSummary(): Promise<RiskSummary> {
  const { data } = await apiClient.get<RiskSummary>(
    "/v1/risk/summary",
  );
  return data;
}
