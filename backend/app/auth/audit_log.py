"""Login audit log for CloudLine.

Each login attempt (success or failure) writes one
record to the cloudline-audit-log table.

Table schema:
    pk:  user_id (UUID)
    sk:  ISO timestamp + "#" + jti  (unique, sortable)

Querying by pk=user_id, sorted descending by sk,
returns the most recent attempts first.
"""

import logging

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)


class AuditLogStore:
    """Stores login audit events in DynamoDB.

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "cloudline-audit-log",
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

    def log_login(
        self,
        user_id: str,
        ip: str,
        user_agent: str,
        success: bool,
        ts: str,
        jti: str = "",
    ) -> bool:
        """Write a login audit record.

        Args:
            user_id: The user's UUID.
            ip: Client IP address.
            user_agent: HTTP User-Agent header.
            success: True = successful login.
            ts: ISO 8601 timestamp.
            jti: JWT ID from the issued token
                (empty string for failed attempts).

        Returns:
            True on success, False on error.
        """
        sk = f"{ts}#{jti}" if jti else ts
        item: dict = {
            "pk": user_id,
            "sk": sk,
            "ip": ip,
            "user_agent": user_agent,
            "success": success,
            "ts": ts,
        }
        if jti:
            item["jti"] = jti
        try:
            self.table.put_item(Item=item)
            return True
        except Exception as e:
            logger.error(
                "audit_log.log_login error: %s", e
            )
            return False

    def get_recent_logins(
        self,
        user_id: str,
        limit: int = 20,
    ) -> list[dict]:
        """Return the most recent login events.

        Args:
            user_id: The user's UUID (pk).
            limit: Maximum number of events to return.

        Returns:
            List of dicts with keys: ip, user_agent,
            success, ts (and jti when present).
            Newest first.
        """
        try:
            resp = self.table.query(
                KeyConditionExpression=(
                    Key("pk").eq(user_id)
                ),
                ScanIndexForward=False,
                Limit=limit,
            )
            return [
                {
                    "ip": item.get("ip", ""),
                    "user_agent": item.get(
                        "user_agent", ""
                    ),
                    "success": item.get(
                        "success", False
                    ),
                    "ts": item.get("ts", ""),
                    "jti": item.get("jti", ""),
                }
                for item in resp.get("Items", [])
            ]
        except Exception as e:
            logger.error(
                "audit_log.get_recent_logins "
                "error: %s", e
            )
            return []
