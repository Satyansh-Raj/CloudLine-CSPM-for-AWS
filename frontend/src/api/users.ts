import { apiClient } from "./client";
import type { User, UserRole } from "@/types/auth";

export interface CreateUserRequest {
  email: string;
  full_name: string;
  role: UserRole;
  initial_password: string;
}

export interface UpdateUserRequest {
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
}

export async function listUsers(): Promise<User[]> {
  const resp = await apiClient.get<User[]>("/v1/users");
  return resp.data;
}

export async function createUser(req: CreateUserRequest): Promise<User> {
  const resp = await apiClient.post<User>("/v1/users", req);
  return resp.data;
}

export async function updateUser(
  userId: string,
  req: UpdateUserRequest,
): Promise<User> {
  const resp = await apiClient.put<User>(`/v1/users/${userId}`, req);
  return resp.data;
}

export async function deleteUser(userId: string): Promise<void> {
  await apiClient.delete(`/v1/users/${userId}`);
}

export async function listResetRequests(): Promise<User[]> {
  const resp = await apiClient.get<User[]>("/v1/users/reset-requests");
  return resp.data;
}

export async function approveReset(userId: string): Promise<void> {
  await apiClient.post(`/v1/users/${userId}/approve-reset`);
}

export async function setUserPassword(
  userId: string,
  newPassword: string,
): Promise<void> {
  await apiClient.post(`/v1/users/${userId}/set-password`, {
    new_password: newPassword,
  });
}

export interface LoginEvent {
  ip: string;
  user_agent: string;
  success: boolean;
  ts: string;
  jti: string;
}

export async function getLoginHistory(userId: string): Promise<LoginEvent[]> {
  const resp = await apiClient.get<LoginEvent[]>(
    `/v1/users/${userId}/login-history`,
  );
  return resp.data;
}
