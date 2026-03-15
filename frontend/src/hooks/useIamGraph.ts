import { useQuery } from "@tanstack/react-query";
import { getIamGraph } from "@/api";
import type { IamGraphResponse } from "@/types";

export function useIamGraph() {
  return useQuery<IamGraphResponse>({
    queryKey: ["iam-graph"],
    queryFn: getIamGraph,
    refetchInterval: 60_000,
    staleTime: 300_000, // 5 min (matches backend cache)
  });
}
