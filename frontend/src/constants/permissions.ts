/**
 * Permission matrix for CloudLine RBAC.
 *
 * Mirrors backend app/auth/permissions.py.
 * Single source of truth for frontend role checks.
 */
import type { UserRole } from "@/types/auth";

export type Action =
  | "view_all"
  | "create_jira_ticket"
  | "trigger_scan"
  | "remediate_violation"
  | "manage_accounts"
  | "manage_users"
  | "approve_password_reset"
  | "change_own_password";

export const PERMISSIONS: Record<UserRole, Set<Action>> =
  {
    admin: new Set<Action>([
      "view_all",
      "create_jira_ticket",
      "trigger_scan",
      "remediate_violation",
      "manage_accounts",
      "manage_users",
      "approve_password_reset",
      "change_own_password",
    ]),
    operator: new Set<Action>([
      "view_all",
      "create_jira_ticket",
      "trigger_scan",
      "remediate_violation",
      "change_own_password",
    ]),
    viewer: new Set<Action>([
      "view_all",
      "change_own_password",
    ]),
  };
