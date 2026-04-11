"""DynamoDB store for the cloudline-users table.

Mirrors the AccountStore pattern. All users share
the partition key "USERS"; sort key is the user_id
(UUID). A GSI on the email field supports lookup
by email for login.
"""

import logging

import boto3
from boto3.dynamodb.conditions import Key

from app.auth.models import User, UserRole

logger = logging.getLogger(__name__)

_PK = "USERS"
_EMAIL_INDEX = "email-index"


class UserStore:
    """Manages CloudLine users in DynamoDB.

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "cloudline-users",
        endpoint_url: str | None = None,
    ):
        kwargs: dict = {}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        dynamodb = session.resource(
            "dynamodb", **kwargs
        )
        self.table = dynamodb.Table(table_name)
        self.table_name = table_name

    def put_user(self, user: User) -> bool:
        """Write or overwrite a User record."""
        item = _user_to_item(user)
        try:
            self.table.put_item(Item=item)
            return True
        except Exception as e:
            logger.error("put_user error: %s", e)
            return False

    def get_user_by_id(
        self, user_id: str
    ) -> User | None:
        """Fetch a single user by UUID.

        Returns:
            User if found, None otherwise.
        """
        try:
            resp = self.table.get_item(
                Key={"pk": _PK, "sk": user_id}
            )
        except Exception as e:
            logger.error(
                "get_user_by_id error: %s", e
            )
            return None

        item = resp.get("Item")
        if not item:
            return None
        return _item_to_user(item)

    def get_user_by_email(
        self, email: str
    ) -> User | None:
        """Fetch a user by email via GSI.

        Returns:
            User if found, None otherwise.
        """
        try:
            resp = self.table.query(
                IndexName=_EMAIL_INDEX,
                KeyConditionExpression=(
                    Key("email").eq(email)
                ),
            )
        except Exception as e:
            logger.error(
                "get_user_by_email error: %s", e
            )
            return None

        items = resp.get("Items", [])
        if not items:
            return None
        return _item_to_user(items[0])

    def list_users(self) -> list[User]:
        """Return all users in the table."""
        try:
            resp = self.table.query(
                KeyConditionExpression=(
                    Key("pk").eq(_PK)
                )
            )
            items = resp.get("Items", [])
            while "LastEvaluatedKey" in resp:
                resp = self.table.query(
                    KeyConditionExpression=(
                        Key("pk").eq(_PK)
                    ),
                    ExclusiveStartKey=(
                        resp["LastEvaluatedKey"]
                    ),
                )
                items.extend(resp.get("Items", []))
            return [_item_to_user(i) for i in items]
        except Exception as e:
            logger.error("list_users error: %s", e)
            return []

    def update_user(
        self,
        user_id: str,
        full_name: str | None = None,
        role: UserRole | None = None,
        is_active: bool | None = None,
    ) -> bool:
        """Update mutable user fields.

        Args:
            user_id: Target user's UUID.
            full_name: New display name, if changing.
            role: New role, if changing.
            is_active: New active flag, if changing.

        Returns:
            True on success, False on error.
        """
        parts: list[str] = []
        values: dict = {}

        if full_name is not None:
            parts.append("full_name = :fn")
            values[":fn"] = full_name
        if role is not None:
            parts.append("#r = :role")
            values[":role"] = role.value
        if is_active is not None:
            parts.append("is_active = :active")
            values[":active"] = is_active

        if not parts:
            return True  # nothing to update

        kwargs: dict = {
            "Key": {"pk": _PK, "sk": user_id},
            "UpdateExpression": (
                "SET " + ", ".join(parts)
            ),
            "ExpressionAttributeValues": values,
        }
        # 'role' is a reserved word in DynamoDB
        if role is not None:
            kwargs["ExpressionAttributeNames"] = {
                "#r": "role"
            }

        try:
            self.table.update_item(**kwargs)
            return True
        except Exception as e:
            logger.error(
                "update_user error: %s", e
            )
            return False

    def update_password_hash(
        self, user_id: str, password_hash: str
    ) -> bool:
        """Replace the stored password hash.

        Args:
            user_id: Target user's UUID.
            password_hash: New bcrypt hash.

        Returns:
            True on success, False on error.
        """
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "SET password_hash = :ph"
                ),
                ExpressionAttributeValues={
                    ":ph": password_hash,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "update_password_hash error: %s", e
            )
            return False

    def set_reset_requested(
        self, user_id: str, timestamp: str
    ) -> bool:
        """Record a password reset request.

        Args:
            user_id: Target user's UUID.
            timestamp: ISO timestamp of the request.

        Returns:
            True on success, False on error.
        """
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "SET reset_requested_at = :ts"
                ),
                ExpressionAttributeValues={
                    ":ts": timestamp,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "set_reset_requested error: %s", e
            )
            return False

    def approve_reset(
        self, user_id: str, approved_by: str
    ) -> bool:
        """Admin approves a password reset request.

        Sets reset_allowed=True and records which
        admin approved the request.

        Args:
            user_id: Target user's UUID.
            approved_by: Approving admin's user_id.

        Returns:
            True on success, False on error.
        """
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "SET reset_allowed = :t, "
                    "reset_approved_by = :by"
                ),
                ExpressionAttributeValues={
                    ":t": True,
                    ":by": approved_by,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "approve_reset error: %s", e
            )
            return False

    def clear_reset_after_change(
        self, user_id: str
    ) -> bool:
        """Clear all reset flags after a successful
        password change.

        Sets reset_allowed=False and removes the
        reset_requested_at and reset_approved_by
        attributes from DynamoDB.

        Args:
            user_id: Target user's UUID.

        Returns:
            True on success, False on error.
        """
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "SET reset_allowed = :f "
                    "REMOVE reset_requested_at, "
                    "reset_approved_by"
                ),
                ExpressionAttributeValues={
                    ":f": False,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "clear_reset_after_change error: "
                "%s", e
            )
            return False

    def increment_failed_login_count(
        self, user_id: str
    ) -> int:
        """Atomically increment failed_login_count.

        Returns:
            New counter value, or 0 on error.
        """
        try:
            resp = self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "ADD failed_login_count :inc"
                ),
                ExpressionAttributeValues={
                    ":inc": 1
                },
                ReturnValues="UPDATED_NEW",
            )
            return int(
                resp.get("Attributes", {}).get(
                    "failed_login_count", 0
                )
            )
        except Exception as e:
            logger.error(
                "increment_failed_login_count "
                "error: %s", e
            )
            return 0

    def reset_failed_login_count(
        self, user_id: str
    ) -> bool:
        """Reset failed_login_count to 0.

        Returns:
            True on success, False on error.
        """
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "SET failed_login_count = :zero"
                ),
                ExpressionAttributeValues={
                    ":zero": 0
                },
            )
            return True
        except Exception as e:
            logger.error(
                "reset_failed_login_count error: "
                "%s", e
            )
            return False

    def update_last_login(
        self, user_id: str, timestamp: str
    ) -> bool:
        """Update the last_login timestamp.

        Args:
            user_id: Target user's UUID.
            timestamp: ISO timestamp of login.

        Returns:
            True on success, False on error.
        """
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": user_id},
                UpdateExpression=(
                    "SET last_login = :ts"
                ),
                ExpressionAttributeValues={
                    ":ts": timestamp,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "update_last_login error: %s", e
            )
            return False


def _user_to_item(user: User) -> dict:
    """Convert User to DynamoDB item (strip Nones)."""
    item = user.model_dump()
    # Convert enum to string value
    if isinstance(item.get("role"), UserRole):
        item["role"] = item["role"].value
    return {
        k: v
        for k, v in item.items()
        if v is not None
    }


def _item_to_user(item: dict) -> User:
    """Convert DynamoDB item to User."""
    return User(**item)
