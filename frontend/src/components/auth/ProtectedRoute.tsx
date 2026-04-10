import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import type { UserRole } from "@/types/auth";

interface ProtectedRouteProps {
  requireRole?: UserRole;
}

export default function ProtectedRoute({
  requireRole,
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div
        role="status"
        className="flex items-center justify-center min-h-screen"
      >
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <Navigate to="/login" state={{ from: location }} replace />
    );
  }

  if (requireRole && user.role !== requireRole) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
