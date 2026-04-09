import { apiClient } from "./client";
import type {
  MacieFinding,
  MacieFindingsParams,
} from "@/types/macie";

export async function getMacieFindings(
  params?: MacieFindingsParams,
): Promise<MacieFinding[]> {
  const { data } = await apiClient.get<MacieFinding[]>(
    "/v1/macie/findings",
    { params },
  );
  return data;
}
