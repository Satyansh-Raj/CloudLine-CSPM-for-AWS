import { apiClient } from "./client";
import type { TrendsHistoryResponse } from "@/types";

export async function getTrendsHistory(
  accountId: string,
  since: string,
): Promise<TrendsHistoryResponse> {
  const { data } = await apiClient.get<TrendsHistoryResponse>(
    "/v1/trends/history",
    { params: { account_id: accountId, since } },
  );
  return data;
}
