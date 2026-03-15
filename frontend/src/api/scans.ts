import { apiClient } from "./client";
import type { ScanResult } from "@/types";

export async function triggerScan(): Promise<ScanResult> {
  const { data } = await apiClient.post<ScanResult>(
    "/v1/scans",
  );
  return data;
}
