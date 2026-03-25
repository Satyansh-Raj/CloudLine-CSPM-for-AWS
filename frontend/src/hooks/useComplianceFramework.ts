import { useQuery } from "@tanstack/react-query";
import {
  getComplianceFrameworks,
  getFrameworkScore,
} from "@/api/compliance";
import type { FrameworkScore } from "@/types";
import { useRegion } from "./useRegion";
import { useAccount } from "./useAccount";

export function useComplianceFrameworks() {
  return useQuery<{ frameworks: string[] }>({
    queryKey: ["compliance", "frameworks"],
    queryFn: getComplianceFrameworks,
    refetchInterval: 30_000,
  });
}

export function useComplianceFramework(framework: string) {
  const { selectedRegion } = useRegion();
  const { selectedAccount } = useAccount();

  return useQuery<FrameworkScore>({
    queryKey: [
      "compliance",
      "framework",
      framework,
      selectedRegion,
      selectedAccount,
    ],
    queryFn: () =>
      getFrameworkScore(framework, {
        region: selectedRegion || undefined,
        account_id: selectedAccount || undefined,
      }),
    refetchInterval: 30_000,
    enabled: framework !== "",
  });
}
