import type { ReactNode } from "react";
import { useAuth } from "@/hooks/useAuth";
import type { UserRole } from "@/types/auth";

interface RoleGateProps {
  allow: UserRole[];
  children: ReactNode;
  fallback?: ReactNode;
}

export default function RoleGate({
  allow,
  children,
  fallback = null,
}: RoleGateProps) {
  const { user } = useAuth();
  const role = user?.role;

  if (!role || !allow.includes(role)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
