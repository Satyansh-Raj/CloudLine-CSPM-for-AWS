import { useQuery } from "@tanstack/react-query";
import { getRiskSummary } from "@/api";
import type { RiskSummary } from "@/types";

export function useRiskSummary(accountId?: string) {
  return useQuery<RiskSummary>({
    queryKey: ["riskSummary", accountId],
    queryFn: () =>
      getRiskSummary(accountId ? { account_id: accountId } : undefined),
    refetchInterval: 30_000,
  });
}
