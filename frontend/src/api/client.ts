import axios from "axios";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "/api";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Error normalizer
export interface ApiError {
  status: number;
  message: string;
  detail?: unknown;
}

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const apiError: ApiError = {
      status: error.response?.status ?? 0,
      message:
        error.response?.data?.detail ??
        error.message ??
        "Unknown error",
      detail: error.response?.data,
    };
    return Promise.reject(apiError);
  },
);
