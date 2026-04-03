import { apiClient } from "./client";
import type {
  Resource,
  InventorySummary,
  InventoryParams,
} from "@/types/inventory";

export async function getInventory(
  params?: InventoryParams,
): Promise<Resource[]> {
  const { data } = await apiClient.get<Resource[]>("/v1/inventory", { params });
  return data;
}

export async function getInventorySummary(
  region?: string,
  accountId?: string,
): Promise<InventorySummary> {
  const params: Record<string, string> = {};
  if (region) params.region = region;
  if (accountId) params.account_id = accountId;
  const { data } = await apiClient.get<InventorySummary>(
    "/v1/inventory/summary",
    {
      params: Object.keys(params).length > 0 ? params : undefined,
    },
  );
  return data;
}

export async function getInventoryDetail(
  resourceType: string,
  resourceId: string,
): Promise<Resource> {
  const { data } = await apiClient.get<Resource>("/v1/inventory/detail", {
    params: {
      resource_type: resourceType,
      resource_id: resourceId,
    },
  });
  return data;
}
