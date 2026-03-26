"""DynamoDB store for the resource-inventory table.

Handles CRUD operations against the resource-inventory
table, including GSI queries for filtered views.
"""

import logging
from datetime import UTC, datetime

import boto3
from boto3.dynamodb.conditions import Key

from app.models.resource import ResourceRecord

logger = logging.getLogger(__name__)

# Numeric fields that DynamoDB returns as Decimal.
_INT_FIELDS = (
    "risk_score",
    "violation_count",
    "critical_violations",
    "high_violations",
)


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


class ResourceStore:
    """Manages resource inventory in DynamoDB.

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "resource-inventory",
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

    def get_resource(
        self,
        account_id: str,
        region: str,
        resource_type: str,
        resource_id: str,
    ) -> ResourceRecord | None:
        """Get a single resource record."""
        pk = f"{account_id}#{region}"
        sk = f"{resource_type}#{resource_id}"

        try:
            resp = self.table.get_item(
                Key={"pk": pk, "sk": sk}
            )
        except Exception as e:
            logger.error(
                "get_resource error: %s", e
            )
            return None

        item = resp.get("Item")
        if not item:
            return None
        return _item_to_resource(item)

    def put_resource(
        self, resource: ResourceRecord
    ) -> bool:
        """Write or overwrite a resource record."""
        item = _resource_to_item(resource)
        try:
            self.table.put_item(Item=item)
            return True
        except Exception as e:
            logger.error(
                "put_resource error: %s", e
            )
            return False

    def query_by_account(
        self,
        account_id: str,
        region: str,
        limit: int = 100,
    ) -> list[ResourceRecord]:
        """Query all resources for an account."""
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
                _item_to_resource(i)
                for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_account error: %s", e
            )
            return []

    def query_by_category(
        self,
        technology_category: str,
        limit: int = 100,
    ) -> list[ResourceRecord]:
        """Query resources by category via GSI."""
        try:
            items = _paginated_query(
                self.table,
                limit,
                IndexName="category-index",
                KeyConditionExpression=(
                    Key("technology_category").eq(
                        technology_category
                    )
                ),
                ScanIndexForward=False,
            )
            return [
                _item_to_resource(i)
                for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_category error: %s", e
            )
            return []

    def query_by_exposure(
        self,
        exposure: str,
        limit: int = 100,
    ) -> list[ResourceRecord]:
        """Query resources by exposure via GSI."""
        try:
            items = _paginated_query(
                self.table,
                limit,
                IndexName="exposure-index",
                KeyConditionExpression=(
                    Key("exposure").eq(exposure)
                ),
                ScanIndexForward=False,
            )
            return [
                _item_to_resource(i)
                for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_exposure error: %s", e
            )
            return []

    def query_by_service(
        self,
        service: str,
        limit: int = 100,
    ) -> list[ResourceRecord]:
        """Query resources by service via GSI."""
        try:
            items = _paginated_query(
                self.table,
                limit,
                IndexName="service-index",
                KeyConditionExpression=(
                    Key("service").eq(service)
                ),
                ScanIndexForward=False,
            )
            return [
                _item_to_resource(i)
                for i in items
            ]
        except Exception as e:
            logger.error(
                "query_by_service error: %s", e
            )
            return []

    def update_security_posture(
        self,
        account_id: str,
        region: str,
        resource_type: str,
        resource_id: str,
        violation_count: int,
        critical_violations: int,
        high_violations: int,
        risk_score: int,
        compliance_gaps: list[str],
    ) -> bool:
        """Update security posture fields."""
        pk = f"{account_id}#{region}"
        sk = f"{resource_type}#{resource_id}"

        update_expr = (
            "SET violation_count = :vc, "
            "critical_violations = :cv, "
            "high_violations = :hv, "
            "risk_score = :rs, "
            "compliance_gaps = :cg"
        )
        expr_values = {
            ":vc": violation_count,
            ":cv": critical_violations,
            ":hv": high_violations,
            ":rs": risk_score,
            ":cg": compliance_gaps,
        }

        try:
            self.table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=(
                    expr_values
                ),
            )
            return True
        except Exception as e:
            logger.error(
                "update_security_posture "
                "error: %s",
                e,
            )
            return False

    def deactivate_resource(
        self,
        account_id: str,
        region: str,
        resource_type: str,
        resource_id: str,
    ) -> bool:
        """Soft-delete: set is_active=False."""
        pk = f"{account_id}#{region}"
        sk = f"{resource_type}#{resource_id}"
        now = (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        try:
            self.table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=(
                    "SET is_active = :false, "
                    "deactivated_at = :now"
                ),
                ExpressionAttributeValues={
                    ":false": False,
                    ":now": now,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "deactivate_resource error: %s", e
            )
            return False

    def delete_resource(
        self,
        account_id: str,
        region: str,
        resource_type: str,
        resource_id: str,
    ) -> bool:
        """Hard-delete a resource record."""
        pk = f"{account_id}#{region}"
        sk = f"{resource_type}#{resource_id}"
        try:
            self.table.delete_item(
                Key={"pk": pk, "sk": sk}
            )
            return True
        except Exception as e:
            logger.error(
                "delete_resource error: %s", e
            )
            return False

    def summary_by_account(
        self,
        account_id: str,
        region: str | None = None,
        regions: list[str] | None = None,
    ) -> list[dict]:
        """Fetch minimal fields for summary counts.

        Returns technology_category, exposure, service,
        and is_active for resources. No hard limit —
        paginates until exhausted.

        Args:
            account_id: AWS account ID.
            region: Single region (backward compat).
            regions: Multiple regions to aggregate.
                Takes precedence over *region*.
        """
        target_regions = (
            regions
            if regions
            else ([region] if region else [])
        )
        items: list[dict] = []
        for rgn in target_regions:
            pk = f"{account_id}#{rgn}"
            kwargs: dict = {
                "KeyConditionExpression": (
                    Key("pk").eq(pk)
                ),
                "ProjectionExpression": (
                    "technology_category, exposure,"
                    " service, is_active"
                ),
            }
            try:
                while True:
                    resp = self.table.query(**kwargs)
                    items.extend(
                        resp.get("Items", [])
                    )
                    lek = resp.get(
                        "LastEvaluatedKey"
                    )
                    if not lek:
                        break
                    kwargs["ExclusiveStartKey"] = lek
            except Exception as e:
                logger.error(
                    "summary_by_account error "
                    "(%s): %s",
                    rgn,
                    e,
                )
        return items

    def count_by_category(
        self, technology_category: str
    ) -> int:
        """Count resources in a category."""
        try:
            return _paginated_count(
                self.table,
                IndexName="category-index",
                KeyConditionExpression=(
                    Key("technology_category").eq(
                        technology_category
                    )
                ),
            )
        except Exception as e:
            logger.error(
                "count_by_category error: %s", e
            )
            return 0


def _resource_to_item(
    resource: ResourceRecord,
) -> dict:
    """Convert ResourceRecord to DynamoDB item."""
    item = resource.model_dump()
    return {
        k: v
        for k, v in item.items()
        if v is not None
    }


def _item_to_resource(
    item: dict,
) -> ResourceRecord:
    """Convert DynamoDB item to ResourceRecord."""
    for field in _INT_FIELDS:
        if field in item:
            item[field] = int(item[field])
    return ResourceRecord(**item)
