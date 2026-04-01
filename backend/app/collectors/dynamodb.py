"""DynamoDB service collector."""

import json
import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class DynamoDBCollector(BaseCollector):
    """Collects DynamoDB table configurations."""

    def collect(self) -> tuple[str, dict]:
        dynamodb = self.session.client(
            "dynamodb"
        )
        autoscaling = self.session.client(
            "application-autoscaling"
        )
        return "dynamodb", {
            "tables": self._get_tables(
                dynamodb, autoscaling
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        dynamodb = self.session.client(
            "dynamodb"
        )
        autoscaling = self.session.client(
            "application-autoscaling"
        )
        try:
            resp = dynamodb.describe_table(
                TableName=resource_id
            )
            return self._build_table(
                dynamodb,
                autoscaling,
                resp["Table"],
            )
        except Exception as e:
            logger.error(
                "DynamoDB describe_table: %s", e
            )
        return {}

    def _get_tables(
        self, dynamodb, autoscaling
    ) -> list[dict]:
        tables = []
        try:
            resp = dynamodb.list_tables()
            for name in resp.get(
                "TableNames", []
            ):
                desc = dynamodb.describe_table(
                    TableName=name
                )
                tables.append(
                    self._build_table(
                        dynamodb,
                        autoscaling,
                        desc["Table"],
                    )
                )
        except Exception as e:
            logger.error(
                "DynamoDB list_tables: %s", e
            )
        return tables

    def _build_table(
        self, dynamodb, autoscaling, table: dict
    ) -> dict:
        arn = table.get("TableArn", "")
        name = table["TableName"]

        sse_desc = self._build_sse_description(
            table
        )
        backups = (
            self._build_continuous_backups(
                dynamodb, name
            )
        )
        deletion = table.get(
            "DeletionProtectionEnabled", False
        )
        policy = self._get_resource_policy(
            dynamodb, arn
        )
        auto_scaling = (
            self._check_auto_scaling(
                autoscaling, name
            )
        )
        tags = self._get_tags(dynamodb, arn)

        return {
            "table_name": name,
            "table_arn": arn,
            "table_status": table.get(
                "TableStatus", "ACTIVE"
            ),
            "billing_mode": table.get(
                "BillingModeSummary", {}
            ).get(
                "BillingMode", "PROVISIONED"
            ),
            "sse_description": sse_desc,
            "continuous_backups": backups,
            "deletion_protection_enabled": (
                deletion
            ),
            "resource_policy": policy,
            "auto_scaling_enabled": auto_scaling,
            "tags": tags,
        }

    # --------------------------------------------------
    # SSE description
    # --------------------------------------------------

    def _build_sse_description(
        self, table: dict
    ) -> dict:
        sse = table.get("SSEDescription", {})
        status = sse.get("Status", "DISABLED")
        sse_type = sse.get("SSEType", "AES256")
        if status != "ENABLED":
            sse_type = "AES256"
        return {
            "status": status,
            "sse_type": sse_type,
        }

    # --------------------------------------------------
    # Continuous backups / PITR
    # --------------------------------------------------

    def _build_continuous_backups(
        self, dynamodb, table_name: str
    ) -> dict:
        pitr_status = "DISABLED"
        try:
            resp = (
                dynamodb
                .describe_continuous_backups(
                    TableName=table_name
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
            pitr_status = pitr_desc.get(
                "PointInTimeRecoveryStatus",
                "DISABLED",
            )
        except Exception as e:
            logger.error(
                "DynamoDB continuous_backups "
                "%s: %s",
                table_name,
                e,
            )
        return {
            "point_in_time_recovery_description": {
                "point_in_time_recovery_status": (
                    pitr_status
                ),
            },
        }

    # --------------------------------------------------
    # Resource policy
    # --------------------------------------------------

    def _get_resource_policy(
        self, dynamodb, arn: str
    ) -> dict:
        """Fetch resource policy for a table.
        Returns dict with Statement list."""
        if not arn:
            return {"Statement": []}
        try:
            resp = (
                dynamodb.describe_resource_policy(
                    ResourceArn=arn
                )
            )
            policy_str = resp.get(
                "Policy", "{}"
            )
            policy = json.loads(policy_str)
            return {
                "Statement": policy.get(
                    "Statement", []
                ),
            }
        except dynamodb.exceptions\
                .PolicyNotFoundException:
            return {"Statement": []}
        except Exception as e:
            logger.error(
                "DynamoDB resource_policy "
                "%s: %s",
                arn,
                e,
            )
        return {"Statement": []}

    # --------------------------------------------------
    # Auto-scaling check
    # --------------------------------------------------

    def _check_auto_scaling(
        self, autoscaling, table_name: str
    ) -> bool:
        """Check if DynamoDB auto-scaling is
        configured via Application Auto Scaling
        scalable targets."""
        try:
            resp = (
                autoscaling
                .describe_scalable_targets(
                    ServiceNamespace="dynamodb",
                    ResourceIds=[
                        "table/" + table_name
                    ],
                )
            )
            targets = resp.get(
                "ScalableTargets", []
            )
            return len(targets) > 0
        except Exception as e:
            logger.error(
                "DynamoDB auto_scaling "
                "%s: %s",
                table_name,
                e,
            )
        return False

    # --------------------------------------------------
    # Tags
    # --------------------------------------------------

    def _get_tags(
        self, dynamodb, arn: str
    ) -> dict:
        tags = {}
        if not arn:
            return tags
        try:
            resp = (
                dynamodb.list_tags_of_resource(
                    ResourceArn=arn
                )
            )
            tags = {
                t["Key"]: t["Value"]
                for t in resp.get("Tags", [])
            }
        except Exception as e:
            logger.error(
                "DynamoDB tags %s: %s",
                arn,
                e,
            )
        return tags
