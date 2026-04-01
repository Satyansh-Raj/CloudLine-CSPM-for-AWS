"""RDS service collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class RDSCollector(BaseCollector):
    """Collects RDS database instance, snapshot,
    and Aurora cluster configurations."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("rds")
        return "rds", {
            "db_instances": (
                self._get_db_instances(client)
            ),
            "db_snapshots": (
                self._get_db_snapshots(client)
            ),
            "db_clusters": (
                self._get_db_clusters(client)
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

    # --------------------------------------------------
    # DB Instances
    # --------------------------------------------------

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
        endpoint = db.get("Endpoint", {})
        port = endpoint.get(
            "Port",
            db.get("DbInstancePort", 0),
        )
        return {
            "db_instance_identifier": db[
                "DBInstanceIdentifier"
            ],
            "db_instance_arn": db.get(
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
            "deletion_protection": db.get(
                "DeletionProtection", False
            ),
            "iam_database_authentication_enabled": (
                db.get(
                    "IAMDatabaseAuthenticationEnabled",
                    False,
                )
            ),
            "enabled_cloudwatch_logs_exports": (
                db.get(
                    "EnabledCloudwatchLogsExports",
                    [],
                )
            ),
            "db_instance_port": port,
            "tags": tags,
        }

    # --------------------------------------------------
    # DB Snapshots
    # --------------------------------------------------

    def _get_db_snapshots(
        self, client
    ) -> list[dict]:
        snapshots = []
        try:
            paginator = client.get_paginator(
                "describe_db_snapshots"
            )
            for page in paginator.paginate(
                IncludePublic=False,
                IncludeShared=False,
            ):
                for snap in page[
                    "DBSnapshots"
                ]:
                    snapshots.append(
                        self._build_snapshot(
                            client, snap
                        )
                    )
        except Exception as e:
            logger.error(
                "RDS describe_db_snapshots: %s",
                e,
            )
        return snapshots

    def _build_snapshot(
        self, client, snap: dict
    ) -> dict:
        snap_id = snap["DBSnapshotIdentifier"]
        attrs = self._get_snapshot_attrs(
            client, snap_id
        )
        return {
            "db_snapshot_identifier": snap_id,
            "db_snapshot_arn": snap.get(
                "DBSnapshotArn", ""
            ),
            "attributes": attrs,
        }

    def _get_snapshot_attrs(
        self, client, snap_id: str
    ) -> dict:
        """Fetch restore attribute for a
        snapshot."""
        restore_ids: list[str] = []
        try:
            resp = (
                client
                .describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap_id
                )
            )
            result = resp.get(
                "DBSnapshotAttributesResult", {}
            )
            for attr in result.get(
                "DBSnapshotAttributes", []
            ):
                if attr.get(
                    "AttributeName"
                ) == "restore":
                    restore_ids = attr.get(
                        "AttributeValues", []
                    )
                    break
        except Exception as e:
            logger.error(
                "RDS snapshot_attributes "
                "%s: %s",
                snap_id,
                e,
            )
        return {"restore": restore_ids}

    # --------------------------------------------------
    # DB Clusters (Aurora)
    # --------------------------------------------------

    def _get_db_clusters(
        self, client
    ) -> list[dict]:
        clusters = []
        try:
            paginator = client.get_paginator(
                "describe_db_clusters"
            )
            for page in paginator.paginate():
                for cl in page["DBClusters"]:
                    clusters.append(
                        self._build_cluster(
                            client, cl
                        )
                    )
        except Exception as e:
            logger.error(
                "RDS describe_db_clusters: %s", e
            )
        return clusters

    def _build_cluster(
        self, client, cl: dict
    ) -> dict:
        tags = {
            t["Key"]: t["Value"]
            for t in cl.get("TagList", [])
        }
        publicly = self._cluster_is_public(
            client, cl
        )
        return {
            "db_cluster_identifier": cl[
                "DBClusterIdentifier"
            ],
            "db_cluster_arn": cl.get(
                "DBClusterArn", ""
            ),
            "engine": cl.get("Engine", ""),
            "publicly_accessible": publicly,
            "storage_encrypted": cl.get(
                "StorageEncrypted", False
            ),
            "deletion_protection": cl.get(
                "DeletionProtection", False
            ),
            "iam_database_authentication_enabled": (
                cl.get(
                    "IAMDatabaseAuthenticationEnabled",
                    False,
                )
            ),
            "backtrack_window": cl.get(
                "BacktrackWindow", 0
            ),
            "tags": tags,
        }

    def _cluster_is_public(
        self, client, cl: dict
    ) -> bool:
        """Check if any member instance of the
        cluster is publicly accessible."""
        members = cl.get(
            "DBClusterMembers", []
        )
        for member in members:
            inst_id = member.get(
                "DBInstanceIdentifier", ""
            )
            if not inst_id:
                continue
            try:
                resp = (
                    client.describe_db_instances(
                        DBInstanceIdentifier=(
                            inst_id
                        )
                    )
                )
                for db in resp.get(
                    "DBInstances", []
                ):
                    if db.get(
                        "PubliclyAccessible",
                        False,
                    ):
                        return True
            except Exception as e:
                logger.error(
                    "RDS cluster member "
                    "%s check: %s",
                    inst_id,
                    e,
                )
        return False
