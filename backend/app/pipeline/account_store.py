"""DynamoDB store for the target-accounts table.

Handles CRUD operations for TargetAccount records,
following the same pattern as StateManager and
ResourceStore.
"""

import logging

import boto3
from boto3.dynamodb.conditions import Key

from app.models.account import TargetAccount

logger = logging.getLogger(__name__)

_PK = "ACCOUNTS"


class AccountStore:
    """Manages target accounts in DynamoDB.

    pk is always "ACCOUNTS" for all records so a
    single DynamoDB query returns all accounts.

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "target-accounts",
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

    def put_account(
        self, account: TargetAccount
    ) -> bool:
        """Write or overwrite a TargetAccount record."""
        item = _account_to_item(account)
        try:
            self.table.put_item(Item=item)
            return True
        except Exception as e:
            logger.error(
                "put_account error: %s", e
            )
            return False

    def get_account(
        self, account_id: str
    ) -> TargetAccount | None:
        """Fetch a single account by ID.

        Returns:
            TargetAccount if found, None otherwise.
        """
        try:
            resp = self.table.get_item(
                Key={"pk": _PK, "sk": account_id}
            )
        except Exception as e:
            logger.error(
                "get_account error: %s", e
            )
            return None

        item = resp.get("Item")
        if not item:
            return None
        return _item_to_account(item)

    def list_active(self) -> list[TargetAccount]:
        """Return all accounts with is_active=True.

        Queries the ACCOUNTS partition and filters
        out inactive records in memory.
        """
        try:
            resp = self.table.query(
                KeyConditionExpression=(
                    Key("pk").eq(_PK)
                )
            )
            items = resp.get("Items", [])
            # Handle pagination
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

            return [
                _item_to_account(i)
                for i in items
                if i.get("is_active", True)
            ]
        except Exception as e:
            logger.error(
                "list_active error: %s", e
            )
            return []

    def deactivate(self, account_id: str) -> bool:
        """Soft-delete: set is_active=False."""
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": account_id},
                UpdateExpression=(
                    "SET is_active = :false"
                ),
                ExpressionAttributeValues={
                    ":false": False,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "deactivate error: %s", e
            )
            return False

    def update_last_scanned(
        self, account_id: str, timestamp: str
    ) -> bool:
        """Update last_scanned timestamp for an account."""
        try:
            self.table.update_item(
                Key={"pk": _PK, "sk": account_id},
                UpdateExpression=(
                    "SET last_scanned = :ts"
                ),
                ExpressionAttributeValues={
                    ":ts": timestamp,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "update_last_scanned error: %s", e
            )
            return False


def _account_to_item(
    account: TargetAccount,
) -> dict:
    """Convert TargetAccount to DynamoDB item."""
    item = account.model_dump()
    return {
        k: v
        for k, v in item.items()
        if v is not None
    }


def _item_to_account(item: dict) -> TargetAccount:
    """Convert DynamoDB item to TargetAccount."""
    return TargetAccount(**item)
