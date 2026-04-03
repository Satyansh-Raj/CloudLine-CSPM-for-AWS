import { useQuery } from "@tanstack/react-query";
import { getComplianceScore } from "@/api";
import type { ComplianceScore } from "@/types";

export function useCompliance(accountId?: string) {
  return useQuery<ComplianceScore>({
    queryKey: ["compliance", accountId],
    queryFn: () => getComplianceScore(accountId),
    refetchInterval: 30_000,
  });
}
