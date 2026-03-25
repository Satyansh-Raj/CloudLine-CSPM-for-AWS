"""RDS service collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class RDSCollector(BaseCollector):
    """Collects RDS database instance configurations."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("rds")
        return "rds", {
            "db_instances": self._get_db_instances(
                client
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("rds")
        try:
            resp = client.describe_db_instances(
                DBInstanceIdentifier=resource_id
            )
            instances = resp.get(
                "DBInstances", []
            )
            if instances:
                return self._build_instance(
                    instances[0]
                )
        except Exception as e:
            logger.error(
                "RDS describe_db_instances: %s", e
            )
        return {}

    def _get_db_instances(
        self, client
    ) -> list[dict]:
        instances = []
        try:
            paginator = client.get_paginator(
                "describe_db_instances"
            )
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    instances.append(
                        self._build_instance(db)
                    )
        except Exception as e:
            logger.error(
                "RDS describe_db_instances: %s", e
            )
        return instances

    def _build_instance(self, db: dict) -> dict:
        tags = {
            t["Key"]: t["Value"]
            for t in db.get("TagList", [])
        }
        return {
            "db_instance_id": db[
                "DBInstanceIdentifier"
            ],
            "arn": db.get(
                "DBInstanceArn", ""
            ),
            "engine": db.get("Engine", ""),
            "publicly_accessible": db.get(
                "PubliclyAccessible", False
            ),
            "storage_encrypted": db.get(
                "StorageEncrypted", False
            ),
            "multi_az": db.get(
                "MultiAZ", False
            ),
            "backup_retention_period": db.get(
                "BackupRetentionPeriod", 0
            ),
            "auto_minor_version_upgrade": db.get(
                "AutoMinorVersionUpgrade", False
            ),
            "tags": tags,
        }
