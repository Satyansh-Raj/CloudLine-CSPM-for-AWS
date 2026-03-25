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
    refetchInterval: 30_000,
  });
}

export function useInventorySummary(region?: string) {
  return useQuery<InventorySummary>({
    queryKey: ["inventory-summary", region],
    queryFn: () => getInventorySummary(region),
    refetchInterval: 30_000,
  });
}
