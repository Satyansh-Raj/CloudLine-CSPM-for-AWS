import { useQuery } from "@tanstack/react-query";
import {
  getViolations,
  type ViolationParams,
} from "@/api";
import type { Violation } from "@/types";

export function useViolations(params?: ViolationParams) {
  return useQuery<Violation[]>({
    queryKey: ["violations", params],
    queryFn: () => getViolations(params),
    refetchInterval: 30_000,
  });
}
