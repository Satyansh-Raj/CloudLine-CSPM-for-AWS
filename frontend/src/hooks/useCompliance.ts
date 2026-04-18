import { useQuery } from "@tanstack/react-query";
import { getComplianceScore } from "@/api";
import type { ComplianceScore } from "@/types";

export function useCompliance(accountId?: string, region?: string) {
  return useQuery<ComplianceScore>({
    queryKey: ["compliance", accountId, region],
    queryFn: () => getComplianceScore(accountId, region),
    refetchInterval: 30_000,
  });
}
