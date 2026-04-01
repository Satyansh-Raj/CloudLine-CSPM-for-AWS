"""S3 service collector."""

import json
import logging
from datetime import datetime, timedelta, timezone

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class S3Collector(BaseCollector):
    """Collects S3 bucket configurations including
    public access, encryption, versioning, and logging."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("s3")
        buckets = []
        try:
            resp = client.list_buckets()
            for b in resp.get("Buckets", []):
                bucket_data = self._get_bucket_details(
                    client, b["Name"]
                )
                if bucket_data:
                    buckets.append(bucket_data)
        except Exception as e:
            logger.error("S3 list_buckets failed: %s", e)
        return "s3", {"buckets": buckets}

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("s3")
        return (
            self._get_bucket_details(
                client, resource_id
            )
            or {}
        )

    def _get_bucket_details(
        self, client, bucket_name: str
    ) -> dict | None:
        try:
            # Get bucket location
            loc = client.get_bucket_location(
                Bucket=bucket_name
            )
            region = (
                loc.get("LocationConstraint")
                or "us-east-1"
            )

            arn = f"arn:aws:s3:::{bucket_name}"

            policy = self._get_bucket_policy(
                client, bucket_name
            )

            return {
                "name": bucket_name,
                "arn": arn,
                "region": region,
                "public_access_block": (
                    self._get_public_access_block(
                        client, bucket_name
                    )
                ),
                "encryption": self._get_encryption(
                    client, bucket_name
                ),
                "versioning": self._get_versioning(
                    client, bucket_name
                ),
                "logging": self._get_logging(
                    client, bucket_name
                ),
                "tags": self._get_tags(
                    client, bucket_name
                ),
                "policy": policy,
                "policy_denies_http": (
                    self._policy_denies_http(policy)
                ),
                "acl": self._get_acl(
                    client, bucket_name
                ),
                "lifecycle_rules": (
                    self._get_lifecycle_rules(
                        client, bucket_name
                    )
                ),
                "object_lock": (
                    self._get_object_lock(
                        client, bucket_name
                    )
                ),
                "cors_rules": (
                    self._get_cors_rules(
                        client, bucket_name
                    )
                ),
                "replication_configuration": (
                    self._get_replication(
                        client, bucket_name
                    )
                ),
                "notification_configuration": (
                    self._get_notifications(
                        client, bucket_name
                    )
                ),
                "size_gb": self._get_size_gb(
                    bucket_name, region
                ),
                "intelligent_tiering_enabled": (
                    self._get_intelligent_tiering(
                        client, bucket_name
                    )
                ),
            }
        except Exception as e:
            logger.error(
                "S3 bucket %s error: %s",
                bucket_name,
                e,
            )
            return None

    def _get_public_access_block(
        self, client, bucket_name: str
    ) -> dict:
        try:
            resp = (
                client.get_public_access_block(
                    Bucket=bucket_name
                )
            )
            cfg = resp[
                "PublicAccessBlockConfiguration"
            ]
            return {
                "block_public_acls": cfg.get(
                    "BlockPublicAcls", False
                ),
                "block_public_policy": cfg.get(
                    "BlockPublicPolicy", False
                ),
                "ignore_public_acls": cfg.get(
                    "IgnorePublicAcls", False
                ),
                "restrict_public_buckets": cfg.get(
                    "RestrictPublicBuckets", False
                ),
            }
        except Exception:
            return {
                "block_public_acls": False,
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False,
            }

    def _get_encryption(
        self, client, bucket_name: str
    ) -> dict:
        """Return encryption config matching Rego
        expected structure with rules list."""
        try:
            resp = (
                client.get_bucket_encryption(
                    Bucket=bucket_name
                )
            )
            raw_rules = resp[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
            rules = []
            for r in raw_rules:
                default = r.get(
                    "ApplyServerSideEncryption"
                    "ByDefault",
                    {},
                )
                entry = {
                    "apply_server_side_encryption"
                    "_by_default": {
                        "sse_algorithm": (
                            default.get(
                                "SSEAlgorithm", ""
                            )
                        ),
                    },
                }
                key_id = default.get(
                    "KMSMasterKeyID"
                )
                if key_id:
                    entry[
                        "apply_server_side_encryption"
                        "_by_default"
                    ]["kms_master_key_id"] = key_id
                rules.append(entry)
            return {"rules": rules}
        except Exception:
            return {"rules": []}

    def _get_versioning(
        self, client, bucket_name: str
    ) -> dict:
        """Return versioning status and MFA delete
        as a dict matching Rego expectations."""
        try:
            resp = client.get_bucket_versioning(
                Bucket=bucket_name
            )
            return {
                "status": resp.get(
                    "Status", "Suspended"
                ),
                "mfa_delete": resp.get(
                    "MFADelete", "Disabled"
                ),
            }
        except Exception:
            return {
                "status": "Suspended",
                "mfa_delete": "Disabled",
            }

    def _get_tags(
        self, client, bucket_name: str
    ) -> dict:
        try:
            resp = client.get_bucket_tagging(
                Bucket=bucket_name
            )
            return {
                t["Key"]: t["Value"]
                for t in resp.get("TagSet", [])
            }
        except Exception:
            return {}

    def _get_logging(
        self, client, bucket_name: str
    ) -> dict:
        try:
            resp = client.get_bucket_logging(
                Bucket=bucket_name
            )
            le = resp.get("LoggingEnabled")
            if le:
                return {
                    "enabled": True,
                    "target_bucket": le.get(
                        "TargetBucket", ""
                    ),
                }
        except Exception:
            pass
        return {
            "enabled": False,
            "target_bucket": None,
        }

    def _get_bucket_policy(
        self, client, bucket_name: str
    ) -> dict:
        """Fetch parsed bucket policy JSON.

        Returns empty Statement list when the bucket
        has no policy attached.
        """
        try:
            resp = client.get_bucket_policy(
                Bucket=bucket_name
            )
            return json.loads(
                resp.get("Policy", "{}")
            )
        except Exception:
            return {"Statement": []}

    @staticmethod
    def _policy_denies_http(policy: dict) -> bool:
        """Check if the policy contains a Deny statement
        for unencrypted (HTTP) access via
        aws:SecureTransport condition."""
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Deny":
                continue
            cond = stmt.get("Condition", {})
            secure = (
                cond.get("Bool", {})
                .get("aws:SecureTransport")
            )
            if secure in ("false", False):
                return True
        return False

    def _get_acl(
        self, client, bucket_name: str
    ) -> dict:
        """Fetch bucket ACL grants."""
        try:
            resp = client.get_bucket_acl(
                Bucket=bucket_name
            )
            grants = []
            for g in resp.get("Grants", []):
                grantee = g.get("Grantee", {})
                grants.append({
                    "grantee": {
                        "type": grantee.get(
                            "Type", ""
                        ),
                        "uri": grantee.get(
                            "URI", ""
                        ),
                    },
                    "permission": g.get(
                        "Permission", ""
                    ),
                })
            return {"grants": grants}
        except Exception:
            return {"grants": []}

    def _get_lifecycle_rules(
        self, client, bucket_name: str
    ) -> list:
        """Fetch bucket lifecycle rules."""
        try:
            resp = (
                client
                .get_bucket_lifecycle_configuration(
                    Bucket=bucket_name
                )
            )
            return resp.get("Rules", [])
        except Exception:
            return []

    def _get_object_lock(
        self, client, bucket_name: str
    ) -> dict:
        """Fetch object lock configuration."""
        try:
            resp = (
                client
                .get_object_lock_configuration(
                    Bucket=bucket_name
                )
            )
            cfg = resp.get(
                "ObjectLockConfiguration", {}
            )
            enabled = (
                cfg.get(
                    "ObjectLockEnabled"
                )
                == "Enabled"
            )
            return {"enabled": enabled}
        except Exception:
            return {"enabled": False}

    def _get_cors_rules(
        self, client, bucket_name: str
    ) -> list:
        """Fetch bucket CORS rules."""
        try:
            resp = client.get_bucket_cors(
                Bucket=bucket_name
            )
            raw = resp.get("CORSRules", [])
            rules = []
            for r in raw:
                rules.append({
                    "allowed_origins": r.get(
                        "AllowedOrigins", []
                    ),
                    "allowed_methods": r.get(
                        "AllowedMethods", []
                    ),
                    "allowed_headers": r.get(
                        "AllowedHeaders", []
                    ),
                    "max_age_seconds": r.get(
                        "MaxAgeSeconds", 0
                    ),
                })
            return rules
        except Exception:
            return []

    def _get_replication(
        self, client, bucket_name: str
    ) -> dict:
        """Fetch bucket replication config."""
        try:
            resp = (
                client.get_bucket_replication(
                    Bucket=bucket_name
                )
            )
            cfg = resp.get(
                "ReplicationConfiguration", {}
            )
            return {
                "rules": cfg.get("Rules", []),
            }
        except Exception:
            return {"rules": []}

    def _get_notifications(
        self, client, bucket_name: str
    ) -> dict | None:
        """Fetch bucket notification config.

        Returns None when no notifications are
        configured.
        """
        try:
            resp = (
                client
                .get_bucket_notification_configuration(
                    Bucket=bucket_name
                )
            )
            resp.pop("ResponseMetadata", None)
            has_config = any(
                resp.get(k)
                for k in (
                    "TopicConfigurations",
                    "QueueConfigurations",
                    "LambdaFunctionConfigurations",
                    "EventBridgeConfiguration",
                )
            )
            return resp if has_config else None
        except Exception:
            return None

    def _get_size_gb(
        self, bucket_name: str, region: str
    ) -> float:
        """Get bucket size in GB via CloudWatch
        BucketSizeBytes metric."""
        try:
            cw = self.session.client(
                "cloudwatch", region_name=region
            )
            now = datetime.now(timezone.utc)
            resp = cw.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="BucketSizeBytes",
                Dimensions=[
                    {
                        "Name": "BucketName",
                        "Value": bucket_name,
                    },
                    {
                        "Name": "StorageType",
                        "Value": "StandardStorage",
                    },
                ],
                StartTime=now - timedelta(days=3),
                EndTime=now,
                Period=86400,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            if not points:
                return 0
            latest = max(
                points,
                key=lambda p: p["Timestamp"],
            )
            size_bytes = latest.get("Average", 0)
            return round(
                size_bytes / (1024 ** 3), 4
            )
        except Exception:
            return 0

    def _get_intelligent_tiering(
        self, client, bucket_name: str
    ) -> bool:
        """Check if intelligent tiering configs
        exist for the bucket."""
        try:
            resp = (
                client
                .list_bucket_intelligent_tiering_configurations(
                    Bucket=bucket_name
                )
            )
            configs = resp.get(
                "IntelligentTieringConfigurationList",
                [],
            )
            return len(configs) > 0
        except Exception:
            return False
