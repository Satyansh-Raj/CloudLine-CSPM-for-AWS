import { useQuery } from "@tanstack/react-query";
import { getComplianceScore } from "@/api";
import type { ComplianceScore } from "@/types";

export function useCompliance() {
  return useQuery<ComplianceScore>({
    queryKey: ["compliance"],
    queryFn: getComplianceScore,
    refetchInterval: 30_000,
  });
}
