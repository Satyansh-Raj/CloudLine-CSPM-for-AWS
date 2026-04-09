"""DynamoDB store for Macie findings.

Handles write and read operations against the
macie-findings table.

Table layout
------------
PK : MACIE#{account_id}
SK : {region}#{finding_id}
GSIs:
  bucket-index   — pk=bucket_name, sk=first_observed_at
  severity-index — pk=severity,    sk=first_observed_at
"""

import logging

import boto3
from boto3.dynamodb.conditions import Key

from app.models.macie import MacieData

logger = logging.getLogger(__name__)


class MacieFindingStore:
    """Manages Macie findings in DynamoDB.

    Attributes:
        table: DynamoDB Table resource.
        table_name: Name of the DynamoDB table.
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "macie-findings",
        endpoint_url: str | None = None,
    ):
        kwargs: dict = {}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        dynamodb = session.resource("dynamodb", **kwargs)
        self.table = dynamodb.Table(table_name)
        self.table_name = table_name

    def put_findings(
        self,
        data: MacieData,
        account_id: str,
        region: str,
    ) -> None:
        """Write all findings from a MacieData object.

        Uses batch_writer for efficiency. Existing items
        with the same PK+SK are overwritten (upsert).

        Args:
            data: MacieData collected from one scan.
            account_id: AWS account ID.
            region: AWS region of the scan.
        """
        if not data.findings:
            return

        pk = f"MACIE#{account_id}"
        with self.table.batch_writer() as batch:
            for finding in data.findings:
                item = {
                    "pk": pk,
                    "sk": f"{region}#{finding.finding_id}",
                    "finding_id": finding.finding_id,
                    "type": finding.type,
                    "bucket_name": finding.bucket_name,
                    "severity": finding.severity,
                    "category": finding.category,
                    "count": finding.count,
                    "first_observed_at": (
                        finding.first_observed_at
                    ),
                    "last_observed_at": (
                        finding.last_observed_at or ""
                    ),
                    "region": region,
                    "account_id": account_id,
                }
                batch.put_item(Item=item)

    def list_findings(
        self,
        account_id: str | None = None,
        bucket_name: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query findings with optional filters.

        Filter priority:
          bucket_name → bucket-index GSI
          severity    → severity-index GSI
          account_id  → primary key query
          (default)   → scan (dev/small datasets)

        Args:
            account_id: Filter by AWS account.
            bucket_name: Filter by S3 bucket name.
            severity: Filter by Macie severity label.
            limit: Maximum number of results.

        Returns:
            List of raw finding dicts.
        """
        try:
            if bucket_name:
                return self._query_by_bucket(
                    bucket_name, limit
                )
            if severity:
                return self._query_by_severity(
                    severity, limit
                )
            if account_id:
                return self._query_by_account(
                    account_id, limit
                )
            # Fallback: scan (not for production use)
            resp = self.table.scan(Limit=limit)
            return resp.get("Items", [])[:limit]
        except Exception as exc:
            logger.error(
                "list_findings error: %s", exc
            )
            return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _query_by_account(
        self, account_id: str, limit: int
    ) -> list[dict]:
        pk = f"MACIE#{account_id}"
        items: list[dict] = []
        kwargs: dict = {
            "KeyConditionExpression": Key("pk").eq(pk),
        }
        while True:
            resp = self.table.query(**kwargs)
            items.extend(resp.get("Items", []))
            if len(items) >= limit:
                return items[:limit]
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return items

    def _query_by_bucket(
        self, bucket_name: str, limit: int
    ) -> list[dict]:
        items: list[dict] = []
        kwargs: dict = {
            "IndexName": "bucket-index",
            "KeyConditionExpression": Key(
                "bucket_name"
            ).eq(bucket_name),
        }
        while True:
            resp = self.table.query(**kwargs)
            items.extend(resp.get("Items", []))
            if len(items) >= limit:
                return items[:limit]
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return items

    def _query_by_severity(
        self, severity: str, limit: int
    ) -> list[dict]:
        items: list[dict] = []
        kwargs: dict = {
            "IndexName": "severity-index",
            "KeyConditionExpression": Key(
                "severity"
            ).eq(severity),
        }
        while True:
            resp = self.table.query(**kwargs)
            items.extend(resp.get("Items", []))
            if len(items) >= limit:
                return items[:limit]
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return items
