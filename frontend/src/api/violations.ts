import { apiClient } from "./client";
import type { Violation } from "@/types";

export interface ViolationParams {
  severity?: string;
  domain?: string;
  status?: string;
}

export async function getViolations(
  params?: ViolationParams,
): Promise<Violation[]> {
  const { data } = await apiClient.get<Violation[]>(
    "/v1/violations",
    { params },
  );
  return data;
}
