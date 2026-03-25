import { apiClient } from "./client";
import type {
  Resource,
  InventorySummary,
  InventoryParams,
} from "@/types/inventory";
import type { SecurityGraph } from "@/types/securityGraph";

export async function getInventory(
  params?: InventoryParams,
): Promise<Resource[]> {
  const { data } = await apiClient.get<Resource[]>("/v1/inventory", { params });
  return data;
}

export async function getInventorySummary(
  region?: string,
): Promise<InventorySummary> {
  const { data } = await apiClient.get<InventorySummary>(
    "/v1/inventory/summary",
    { params: region ? { region } : undefined },
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

export async function getSecurityGraph(params?: {
  region?: string;
  account_id?: string;
}): Promise<SecurityGraph> {
  const { data } = await apiClient.get<SecurityGraph>("/v1/inventory/graph", {
    params,
  });
  return data;
}
