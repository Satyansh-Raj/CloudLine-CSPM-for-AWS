import { useQuery } from "@tanstack/react-query";
import { getRiskSummary } from "@/api";
import type { RiskSummary } from "@/types";

export function useRiskSummary() {
  return useQuery<RiskSummary>({
    queryKey: ["riskSummary"],
    queryFn: getRiskSummary,
    refetchInterval: 30_000,
  });
}
