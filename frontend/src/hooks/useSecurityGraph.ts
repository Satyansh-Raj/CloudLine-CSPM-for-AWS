import { useQuery } from "@tanstack/react-query";
import { getSecurityGraph } from "@/api/inventory";
import { useRegion } from "@/hooks/useRegion";
import { useAccount } from "@/hooks/useAccount";
import type { SecurityGraph } from "@/types/securityGraph";

export function useSecurityGraph() {
  const { selectedRegion } = useRegion();
  const { selectedAccount } = useAccount();

  return useQuery<SecurityGraph>({
    queryKey: [
      "security-graph",
      selectedRegion,
      selectedAccount,
    ],
    queryFn: () =>
      getSecurityGraph({
        region: selectedRegion || undefined,
        account_id: selectedAccount || undefined,
      }),
    refetchInterval: 30_000,
  });
}
