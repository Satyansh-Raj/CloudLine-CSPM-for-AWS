import { apiClient } from "./client";
import type { ScanResult } from "@/types";

export async function triggerScan(
  accountId?: string,
): Promise<ScanResult> {
  const { data } = await apiClient.post<ScanResult>(
    "/v1/scans",
    undefined,
    {
      params: accountId ? { account_id: accountId } : undefined,
    },
  );
  return data;
}
