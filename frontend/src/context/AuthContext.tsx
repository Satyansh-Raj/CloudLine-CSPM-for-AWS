import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import { login as loginApi, getMe } from "@/api/auth";
import type {
<<<<<<< HEAD
=======
  AuthContextValue,
>>>>>>> 1134ea2 (Forget Password Error Fix)
  LoginCredentials,
  User,
} from "@/types/auth";
import { AuthContext } from "./authContextValue";

export const AUTH_KEY = "cloudline.auth.v1";

export function AuthProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Hydrate from localStorage on mount.
  useEffect(() => {
    const stored = localStorage.getItem(AUTH_KEY);
    if (!stored) {
      setIsLoading(false);
      return;
    }
    getMe()
      .then(setUser)
      .catch(() => {
        localStorage.removeItem(AUTH_KEY);
      })
      .finally(() => setIsLoading(false));
  }, []);

  // Listen for auth:logout CustomEvent broadcast
  // by the apiClient when a token refresh fails.
  useEffect(() => {
    const handler = () => {
      setUser(null);
      localStorage.removeItem(AUTH_KEY);
    };
    window.addEventListener("auth:logout", handler);
    return () =>
      window.removeEventListener(
        "auth:logout",
        handler,
      );
  }, []);

  const login = useCallback(
<<<<<<< HEAD
    async (credentials: LoginCredentials) => {
=======
    async (credentials: LoginCredentials): Promise<User> => {
>>>>>>> 1134ea2 (Forget Password Error Fix)
      const tokens = await loginApi(credentials);
      localStorage.setItem(
        AUTH_KEY,
        JSON.stringify({
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
        }),
      );
      const me = await getMe();
      setUser(me);
<<<<<<< HEAD
=======
      return me;
>>>>>>> 1134ea2 (Forget Password Error Fix)
    },
    [],
  );

  const logout = useCallback(() => {
    localStorage.removeItem(AUTH_KEY);
    setUser(null);
  }, []);

  const refreshMe = useCallback(async () => {
    const me = await getMe();
    setUser(me);
  }, []);

<<<<<<< HEAD
  const value = useMemo(
=======
  const value = useMemo<AuthContextValue>(
>>>>>>> 1134ea2 (Forget Password Error Fix)
    () => ({
      user,
      isLoading,
      login,
      logout,
      refreshMe,
    }),
    [user, isLoading, login, logout, refreshMe],
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
