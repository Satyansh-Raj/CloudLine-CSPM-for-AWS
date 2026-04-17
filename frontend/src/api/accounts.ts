import { apiClient } from "./client";
import type {
  TargetAccount,
  CreateAccountPayload,
  PreflightRequest,
  PreflightResponse,
} from "@/types/account";

export async function preflight(
  payload: PreflightRequest,
): Promise<PreflightResponse> {
  const { data } = await apiClient.post<PreflightResponse>(
    "/v1/accounts/preflight",
    payload,
  );
  return data;
}

export async function getAccounts(): Promise<TargetAccount[]> {
  const { data } = await apiClient.get<TargetAccount[]>("/v1/accounts");
  return data;
}

export async function createAccount(
  payload: CreateAccountPayload,
): Promise<TargetAccount> {
  const { data } = await apiClient.post<TargetAccount>("/v1/accounts", payload);
  return data;
}

export async function deleteAccount(accountId: string): Promise<void> {
  await apiClient.delete(`/v1/accounts/${accountId}`);
}
