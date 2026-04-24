import { apiClient } from "./client";
import type {
  LoginCredentials,
  TokenPair,
  User,
} from "@/types/auth";

export async function login(
  credentials: LoginCredentials,
): Promise<TokenPair> {
  const resp = await apiClient.post<TokenPair>(
    "/v1/auth/login",
    credentials,
  );
  return resp.data;
}

export async function logout(): Promise<void> {
  await apiClient.post("/v1/auth/logout");
}

export async function refreshToken(
  refresh_token: string,
): Promise<TokenPair> {
  const resp = await apiClient.post<TokenPair>(
    "/v1/auth/refresh",
    { refresh_token },
  );
  return resp.data;
}

export async function getMe(): Promise<User> {
  const resp = await apiClient.get<User>(
    "/v1/auth/me",
  );
  return resp.data;
}

export async function changePassword(
  current_password: string,
  new_password: string,
): Promise<void> {
  await apiClient.post("/v1/auth/change-password", {
    current_password,
    new_password,
  });
}

export async function requestPasswordReset(
  email: string,
): Promise<void> {
  await apiClient.post("/v1/auth/request-reset", {
    email,
  });
}
<<<<<<< HEAD
=======

export async function resetPassword(
  email: string,
  new_password: string,
): Promise<void> {
  await apiClient.post("/v1/auth/reset-password", {
    email,
    new_password,
  });
}
>>>>>>> 1134ea2 (Forget Password Error Fix)
