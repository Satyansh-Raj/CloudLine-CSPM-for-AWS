"""Permission matrix for CloudLine RBAC.

Single source of truth mirrored by the frontend
constants/permissions.ts. Each role maps to the
set of action strings it is allowed to perform.
"""

from app.auth.models import UserRole

PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.ADMIN: {
        "view_all",
        "create_jira_ticket",
        "trigger_scan",
        "remediate_violation",
        "manage_accounts",
        "manage_users",
        "approve_password_reset",
        "change_own_password",
    },
    UserRole.OPERATOR: {
        "view_all",
        "create_jira_ticket",
        "trigger_scan",
        "remediate_violation",
        "change_own_password",
    },
    UserRole.VIEWER: {
        "view_all",
        "change_own_password",
    },
}
