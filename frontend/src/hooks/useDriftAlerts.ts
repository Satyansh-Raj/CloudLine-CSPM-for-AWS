import { useQuery } from "@tanstack/react-query";
import { getDriftAlerts } from "@/api";
import type {
  DriftAlertParams,
  DriftAlertsResponse,
} from "@/types";

export function useDriftAlerts(
  params?: DriftAlertParams,
) {
  return useQuery<DriftAlertsResponse>({
    queryKey: ["driftAlerts", params],
    queryFn: () => getDriftAlerts(params),
    refetchInterval: 30_000,
  });
}
