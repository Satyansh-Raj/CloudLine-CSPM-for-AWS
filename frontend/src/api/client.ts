import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

export interface ApiError {
  status: number;
  message: string;
  detail?: unknown;
}

// ── Auth token storage key ────────────────────────
export const AUTH_STORAGE_KEY = "cloudline.auth.v1";

// ── Request interceptor: attach access token ──────
apiClient.interceptors.request.use((config) => {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (stored) {
      const { accessToken } = JSON.parse(stored) as {
        accessToken?: string;
      };
      if (accessToken) {
        config.headers["Authorization"] = `Bearer ${accessToken}`;
      }
    }
  } catch {
    // Malformed storage — skip silently.
  }
  return config;
});

// ── Single-flight refresh ─────────────────────────
let _refreshPromise: Promise<string> | null = null;

async function _doRefresh(): Promise<string> {
  const stored = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!stored) throw new Error("No auth tokens stored");
  const { refreshToken } = JSON.parse(stored) as {
    refreshToken?: string;
  };
  if (!refreshToken) throw new Error("No refresh token");

  // Use bare axios to avoid triggering our interceptor.
  const resp = await axios.post(`${API_BASE_URL}/v1/auth/refresh`, {
    refresh_token: refreshToken,
  });
  const { access_token, refresh_token: newRefresh } = resp.data as {
    access_token: string;
    refresh_token: string;
  };
  localStorage.setItem(
    AUTH_STORAGE_KEY,
    JSON.stringify({
      accessToken: access_token,
      refreshToken: newRefresh,
    }),
  );
  return access_token;
}

function _singleFlightRefresh(): Promise<string> {
  if (!_refreshPromise) {
    _refreshPromise = _doRefresh().finally(() => {
      _refreshPromise = null;
    });
  }
  return _refreshPromise;
}

// ── Response interceptor: 401 → refresh → retry ──
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config as
      | (typeof error.config & { _retry?: boolean })
      | undefined;

    if (error.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      try {
        const newToken = await _singleFlightRefresh();
        original.headers["Authorization"] = `Bearer ${newToken}`;
        // Notify SessionExpiryWarning to reschedule
        // its timer for the new token's expiry.
        window.dispatchEvent(new CustomEvent("auth:token-refreshed"));
        return apiClient(original);
      } catch {
        // Refresh failed — signal global logout.
        window.dispatchEvent(new CustomEvent("auth:logout"));
      }
    }

    // Normalize error shape (existing behavior).
    const detail = error.response?.data?.detail;
    const message =
      typeof detail === "string"
        ? detail
        : detail !== null && typeof detail === "object" && "message" in detail
          ? String((detail as { message: unknown }).message)
          : (error.message ?? "Unknown error");
    const apiError: ApiError = {
      status: error.response?.status ?? 0,
      message,
      detail: error.response?.data,
    };
    return Promise.reject(apiError);
  },
);
