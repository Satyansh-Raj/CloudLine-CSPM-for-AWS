import {
  PERMISSIONS,
  type Action,
} from "@/constants/permissions";
import { useAuth } from "./useAuth";

interface UsePermissionResult {
  role: string;
  can: (action: Action) => boolean;
}

export function usePermission(): UsePermissionResult {
  const { user } = useAuth();
  const role = user?.role ?? "viewer";

  return {
    role,
    can: (action: Action): boolean => {
      const perms =
        PERMISSIONS[role as keyof typeof PERMISSIONS] ??
        new Set();
      return perms.has(action);
    },
  };
}
