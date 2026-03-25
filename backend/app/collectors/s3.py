"""S3 service collector."""

import logging

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
                "mfa_delete": self._get_mfa_delete(
                    client, bucket_name
                ),
                "logging": self._get_logging(
                    client, bucket_name
                ),
                "tags": self._get_tags(
                    client, bucket_name
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
        try:
            resp = (
                client.get_bucket_encryption(
                    Bucket=bucket_name
                )
            )
            rules = resp[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
            if rules:
                rule = rules[0][
                    "ApplyServerSideEncryptionByDefault"
                ]
                return {
                    "enabled": True,
                    "type": rule.get(
                        "SSEAlgorithm", ""
                    ),
                    "kms_key_id": rule.get(
                        "KMSMasterKeyID"
                    ),
                }
        except Exception:
            pass
        return {
            "enabled": False,
            "type": None,
            "kms_key_id": None,
        }

    def _get_versioning(
        self, client, bucket_name: str
    ) -> bool:
        try:
            resp = client.get_bucket_versioning(
                Bucket=bucket_name
            )
            return (
                resp.get("Status") == "Enabled"
            )
        except Exception:
            return False

    def _get_mfa_delete(
        self, client, bucket_name: str
    ) -> bool:
        try:
            resp = client.get_bucket_versioning(
                Bucket=bucket_name
            )
            return (
                resp.get("MFADelete") == "Enabled"
            )
        except Exception:
            return False

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
