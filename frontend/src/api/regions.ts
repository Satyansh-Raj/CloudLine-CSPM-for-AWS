import { apiClient } from "./client";

export interface RegionsResponse {
  regions: string[];
  default: string;
}

export async function getRegions(): Promise<RegionsResponse> {
  const { data } =
    await apiClient.get<RegionsResponse>(
      "/v1/inventory/regions",
    );
  return data;
}
