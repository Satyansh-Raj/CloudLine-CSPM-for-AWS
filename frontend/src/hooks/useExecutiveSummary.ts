import { useQuery } from "@tanstack/react-query";
import {
  getExecutiveSummary,
  type ExecutiveSummaryParams,
} from "@/api";
import type { ExecutiveSummary } from "@/types";

export function useExecutiveSummary(
  params?: ExecutiveSummaryParams,
) {
  return useQuery<ExecutiveSummary>({
    queryKey: ["executiveSummary", params],
    queryFn: () => getExecutiveSummary(params),
    refetchInterval: 30_000,
  });
}
