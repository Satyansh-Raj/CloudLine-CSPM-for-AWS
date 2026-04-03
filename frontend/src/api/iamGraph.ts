import { apiClient } from "./client";
import type { IamGraphResponse } from "@/types";

export async function getIamGraph(
  accountId?: string,
): Promise<IamGraphResponse> {
  const { data } = await apiClient.get<IamGraphResponse>(
    "/v1/iam/graph",
    {
      params: accountId ? { account_id: accountId } : undefined,
    },
  );
  return data;
}
