import { useQuery } from "@tanstack/react-query";
import { getIamGraph } from "@/api";
import type { IamGraphResponse } from "@/types";

export function useIamGraph(accountId?: string) {
  return useQuery<IamGraphResponse>({
    queryKey: ["iam-graph", accountId],
    queryFn: () => getIamGraph(accountId),
    refetchInterval: 60_000,
    staleTime: 300_000, // 5 min (matches backend cache)
  });
}
