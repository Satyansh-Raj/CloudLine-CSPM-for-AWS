import { useQuery } from "@tanstack/react-query";
import { getInventory, getInventorySummary } from "@/api/inventory";
import type {
  Resource,
  InventorySummary,
  InventoryParams,
} from "@/types/inventory";

export function useInventory(params?: InventoryParams) {
  return useQuery<Resource[]>({
    queryKey: ["inventory", params],
    queryFn: () => getInventory(params),
    staleTime: 0,
    refetchOnMount: "always",
    refetchInterval: 30_000,
  });
}

export function useInventorySummary(region?: string, accountId?: string) {
  return useQuery<InventorySummary>({
    queryKey: ["inventory-summary", region, accountId],
    queryFn: () => getInventorySummary(region, accountId),
    staleTime: 0,
    refetchOnMount: "always",
    refetchInterval: 30_000,
  });
}
