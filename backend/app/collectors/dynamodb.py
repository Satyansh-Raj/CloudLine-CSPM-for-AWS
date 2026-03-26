"""DynamoDB service collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class DynamoDBCollector(BaseCollector):
    """Collects DynamoDB table configurations."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("dynamodb")
        return "dynamodb", {
            "tables": self._get_tables(client),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("dynamodb")
        try:
            resp = client.describe_table(
                TableName=resource_id
            )
            return self._build_table(
                client, resp["Table"]
            )
        except Exception as e:
            logger.error(
                "DynamoDB describe_table: %s", e
            )
        return {}

    def _get_tables(
        self, client
    ) -> list[dict]:
        tables = []
        try:
            resp = client.list_tables()
            for name in resp.get(
                "TableNames", []
            ):
                desc = client.describe_table(
                    TableName=name
                )
                tables.append(
                    self._build_table(
                        client, desc["Table"]
                    )
                )
        except Exception as e:
            logger.error(
                "DynamoDB list_tables: %s", e
            )
        return tables

    def _build_table(
        self, client, table: dict
    ) -> dict:
        arn = table.get("TableArn", "")
        sse = table.get(
            "SSEDescription", {}
        )
        encryption_type = sse.get(
            "SSEType", ""
        ) if sse.get("Status") == "ENABLED" else ""

        pitr = False
        try:
            resp = (
                client
                .describe_continuous_backups(
                    TableName=table["TableName"]
                )
            )
            desc = resp.get(
                "ContinuousBackupsDescription",
                {},
            )
            pitr_desc = desc.get(
                "PointInTimeRecoveryDescription",
                {},
            )
            pitr = (
                pitr_desc.get(
                    "PointInTimeRecoveryStatus"
                )
                == "ENABLED"
            )
        except Exception:
            pass

        tags = {}
        try:
            tag_resp = client.list_tags_of_resource(
                ResourceArn=arn
            )
            tags = {
                t["Key"]: t["Value"]
                for t in tag_resp.get("Tags", [])
            }
        except Exception:
            pass

        return {
            "table_name": table["TableName"],
            "arn": arn,
            "table_status": table.get(
                "TableStatus", "ACTIVE"
            ),
            "billing_mode": table.get(
                "BillingModeSummary", {}
            ).get(
                "BillingMode", "PROVISIONED"
            ),
            "encryption_type": encryption_type,
            "point_in_time_recovery": pitr,
            "tags": tags,
        }
