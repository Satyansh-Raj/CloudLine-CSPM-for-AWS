import { apiClient } from "./client";
import type { IamGraphResponse } from "@/types";

export async function getIamGraph(): Promise<
  IamGraphResponse
> {
  const { data } =
    await apiClient.get<IamGraphResponse>(
      "/v1/iam/graph",
    );
  return data;
}
