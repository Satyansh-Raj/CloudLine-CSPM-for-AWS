"""DynamoDB state manager for violation tracking.

Handles CRUD operations against the violation-state
table, including GSI queries for filtered views.
"""

import logging
from datetime import UTC, datetime

import boto3
from boto3.dynamodb.conditions import Key

from app.pipeline.models import ViolationState

logger = logging.getLogger(__name__)


def _paginated_query(table, limit, **kwargs):
    """Run a DynamoDB query with pagination.

    Handles LastEvaluatedKey to fetch across 1MB
    page boundaries. Stops when limit is reached
    or no more pages remain.

    Args:
        table: DynamoDB Table resource.
        limit: Max items to collect.
        **kwargs: Passed to table.query().

    Returns:
        List of raw DynamoDB items.
    """
    items = []
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if len(items) >= limit:
            return items[:limit]
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _paginated_count(table, **kwargs):
    """Run a DynamoDB COUNT query with pagination.

    Args:
        table: DynamoDB Table resource.
        **kwargs: Passed to table.query().

    Returns:
        Total count across all pages.
    """
    total = 0
    kwargs["Select"] = "COUNT"
    while True:
        resp = table.query(**kwargs)
        total += resp.get("Count", 0)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return total


class StateManager:
    """Manages violation state in DynamoDB.

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "violation-state",
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

    def get_state(
        self,
        account_id: str,
        region: str,
        check_id: str,
        resource_arn: str,
    ) -> ViolationState | None:
        """Get a single violation state record."""
        pk = f"{account_id}#{region}"
        sk = f"{check_id}#{resource_arn}"

        try:
            resp = self.table.get_item(
                Key={"pk": pk, "sk": sk}
            )
        except Exception as e:
            logger.error(
                "get_state error: %s", e
            )
            return None

        item = resp.get("Item")
        if not item:
            return None
        return _item_to_state(item)

    def put_state(
        self, state: ViolationState
    ) -> bool:
        """Write or overwrite a violation state."""
        item = _state_to_item(state)
        try:
            self.table.put_item(Item=item)
            return True
        except Exception as e:
            logger.error(
                "put_state error: %s", e
            )
            return False

    def update_status(
        self,
        account_id: str,
        region: str,
        check_id: str,
        resource_arn: str,
        new_status: str,
        reason: str = "",
        risk_score: int = 0,
    ) -> bool:
        """Update the status of an existing record.

        Sets previous_status to the OLD status before
        overwriting with new_status.
        """
        pk = f"{account_id}#{region}"
        sk = f"{check_id}#{resource_arn}"
        now = (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        # DynamoDB resolves all attribute references
        # against the item's CURRENT stored values
        # before applying any writes. So
        # previous_status = #st captures the stored
        # status before this update overwrites it.
        update_expr = (
            "SET previous_status = #st, "
            "#st = :new_status, "
            "last_evaluated = :now, "
            "reason = :reason, "
            "risk_score = :score"
        )
        expr_names = {"#st": "status"}
        expr_values = {
            ":new_status": new_status,
            ":now": now,
            ":reason": reason,
            ":score": risk_score,
        }

        if new_status == "ok":
            update_expr += ", resolved_at = :now"

        try:
            self.table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=(
                    expr_names
                ),
                ExpressionAttributeValues=(
                    expr_values
                ),
            )
            return True
        except Exception as e:
            logger.error(
                "update_status error: %s", e
            )
            return False

    def query_by_account(
        self,
        account_id: str,
        region: str,
        limit: int = 100,
    ) -> list[ViolationState]:
        """Query all violations for an account."""
        pk = f"{account_id}#{region}"
        try:
            items = _paginated_query(
                self.table,
                limit,
                KeyConditionExpression=(
                    Key("pk").eq(pk)
                ),
            )
            return [
                _item_to_state(i) for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_account error: %s", e
            )
            return []

    def query_by_status(
        self,
        status: str,
        limit: int = 100,
    ) -> list[ViolationState]:
        """Query violations by status via GSI-1."""
        try:
            items = _paginated_query(
                self.table,
                limit,
                IndexName="status-index",
                KeyConditionExpression=(
                    Key("status").eq(status)
                ),
                ScanIndexForward=False,
            )
            return [
                _item_to_state(i) for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_status error: %s", e
            )
            return []

    def query_by_domain(
        self,
        domain: str,
        limit: int = 100,
    ) -> list[ViolationState]:
        """Query violations by domain via GSI-2."""
        try:
            items = _paginated_query(
                self.table,
                limit,
                IndexName="domain-index",
                KeyConditionExpression=(
                    Key("domain").eq(domain)
                ),
                ScanIndexForward=False,
            )
            return [
                _item_to_state(i) for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_domain error: %s", e
            )
            return []

    def query_by_check(
        self,
        check_id: str,
        limit: int = 100,
    ) -> list[ViolationState]:
        """Query violations by check_id via GSI-3."""
        try:
            items = _paginated_query(
                self.table,
                limit,
                IndexName="check-index",
                KeyConditionExpression=(
                    Key("check_id").eq(check_id)
                ),
            )
            return [
                _item_to_state(i) for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_check error: %s", e
            )
            return []

    def delete_state(
        self,
        account_id: str,
        region: str,
        check_id: str,
        resource_arn: str,
    ) -> bool:
        """Delete a violation state record."""
        pk = f"{account_id}#{region}"
        sk = f"{check_id}#{resource_arn}"
        try:
            self.table.delete_item(
                Key={"pk": pk, "sk": sk}
            )
            return True
        except Exception as e:
            logger.error(
                "delete_state error: %s", e
            )
            return False

    def count_by_status(
        self, status: str
    ) -> int:
        """Count violations with a given status."""
        try:
            return _paginated_count(
                self.table,
                IndexName="status-index",
                KeyConditionExpression=(
                    Key("status").eq(status)
                ),
            )
        except Exception as e:
            logger.error(
                "count_by_status error: %s", e
            )
            return 0


def _state_to_item(
    state: ViolationState,
) -> dict:
    """Convert ViolationState to DynamoDB item."""
    item = state.model_dump()
    return {
        k: v
        for k, v in item.items()
        if v is not None
    }


def _item_to_state(item: dict) -> ViolationState:
    """Convert DynamoDB item to ViolationState."""
    if "risk_score" in item:
        item["risk_score"] = int(
            item["risk_score"]
        )
    if "regression_count" in item:
        item["regression_count"] = int(
            item["regression_count"]
        )
    if "ttl" in item:
        item["ttl"] = (
            int(item["ttl"])
            if item["ttl"]
            else None
        )
    return ViolationState(**item)
