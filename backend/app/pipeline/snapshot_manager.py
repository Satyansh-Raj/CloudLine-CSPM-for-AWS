"""DynamoDB snapshot manager for daily compliance trends.

Writes one record per account per scan day to the
compliance-trends table (PK=account_id, SK=YYYY-MM-DD).
Enables accurate historical active-violation counts on
the Trends page without relying on violation-state
last_evaluated timestamps (which are overwritten each scan).
"""

import logging
from datetime import UTC, datetime

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)


class SnapshotManager:
    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "compliance-trends",
        endpoint_url: str | None = None,
    ):
        kwargs: dict = {}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        dynamodb = session.resource(
            "dynamodb", **kwargs
        )
        self.table = dynamodb.Table(table_name)

    def save_snapshot(
        self,
        account_id: str,
        date: str,
        active: int,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
    ) -> bool:
        """Write (or overwrite) the daily snapshot."""
        try:
            self.table.put_item(Item={
                "pk": account_id,
                "sk": date,
                "active": active,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "scanned_at": (
                    datetime.now(UTC)
                    .isoformat()
                    .replace("+00:00", "Z")
                ),
            })
            return True
        except Exception as e:
            logger.error(
                "save_snapshot error: %s", e
            )
            return False

    def get_snapshots(
        self,
        account_id: str,
        since: str,
        until: str | None = None,
    ) -> list[dict]:
        """Query snapshots for account in date range.

        Args:
            account_id: AWS account ID.
            since: Start date YYYY-MM-DD (inclusive).
            until: End date YYYY-MM-DD (inclusive).
                   Defaults to today.

        Returns:
            List of snapshot dicts ordered by date asc.
        """
        if until is None:
            until = datetime.now(UTC).strftime(
                "%Y-%m-%d"
            )
        try:
            resp = self.table.query(
                KeyConditionExpression=(
                    Key("pk").eq(account_id)
                    & Key("sk").between(since, until)
                ),
            )
            return [
                {
                    "date": item["sk"],
                    "active": int(
                        item.get("active", 0)
                    ),
                    "critical": int(
                        item.get("critical", 0)
                    ),
                    "high": int(item.get("high", 0)),
                    "medium": int(
                        item.get("medium", 0)
                    ),
                    "low": int(item.get("low", 0)),
                }
                for item in resp.get("Items", [])
            ]
        except Exception as e:
            logger.error(
                "get_snapshots error: %s", e
            )
            return []
