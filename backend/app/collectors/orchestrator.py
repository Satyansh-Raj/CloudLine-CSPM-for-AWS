"""Collection orchestrator — runs all collectors and
merges results into the unified JSON document."""

import logging
from datetime import datetime, timezone

import boto3

from app.collectors.apigateway import (
    APIGatewayCollector,
)
from app.collectors.cdn import CDNCollector
from app.collectors.container import ContainerCollector
from app.collectors.dynamodb import DynamoDBCollector
from app.collectors.ec2 import EC2Collector
from app.collectors.elb import ELBCollector
from app.collectors.iam import IAMCollector
from app.collectors.kms import KMSCollector
from app.collectors.lambda_collector import (
    LambdaCollector,
)
from app.collectors.logging_collector import (
    LoggingCollector,
)
from app.collectors.rds import RDSCollector
from app.collectors.s3 import S3Collector
from app.collectors.vpc import VPCCollector

logger = logging.getLogger(__name__)

# IAM is a global service — collected once per scan
# regardless of how many regions are scanned.
GLOBAL_COLLECTORS = {
    "iam": IAMCollector,
}

# These collectors are region-scoped and run once per
# region in a multi-region scan.
REGIONAL_COLLECTORS = {
    "s3": S3Collector,
    "ec2": EC2Collector,
    "vpc": VPCCollector,
    "rds": RDSCollector,
    "lambda": LambdaCollector,
    "logging": LoggingCollector,
    "kms": KMSCollector,
    "elb": ELBCollector,
    "cdn": CDNCollector,
    "dynamodb": DynamoDBCollector,
    "apigateway": APIGatewayCollector,
    "containers": ContainerCollector,
}

# Full map preserved for backward compatibility.
COLLECTOR_MAP = {
    **GLOBAL_COLLECTORS,
    **REGIONAL_COLLECTORS,
}


class CollectionOrchestrator:
    """Runs all collectors and merges results into
    the unified JSON schema."""

    def __init__(
        self,
        session: boto3.Session,
        account_id: str,
        region: str,
    ):
        self.session = session
        self.account_id = account_id
        self.region = region
        self.collectors = [
            cls(session, account_id, region)
            if cls is EC2Collector
            else cls(session)
            for cls in COLLECTOR_MAP.values()
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_collectors(
        self, collectors: list
    ) -> dict:
        """Run *collectors* and return merged data dict.

        Does NOT include top-level metadata keys
        (account_id, region, …) — callers add those.
        """
        data: dict = {}
        errors: list[str] = []
        for collector in collectors:
            name = collector.__class__.__name__
            try:
                if isinstance(
                    collector, KMSCollector
                ):
                    extra = collector.collect_full()
                    data["kms"] = extra.get(
                        "kms", {"keys": []}
                    )
                    data[
                        "secrets_manager"
                    ] = extra.get(
                        "secrets_manager",
                        {"secrets": []},
                    )
                    data["backup"] = extra.get(
                        "backup",
                        {
                            "plans": [],
                            "protected_resources": [],
                        },
                    )
                else:
                    key, svc_data = collector.collect()
                    data[key] = svc_data
            except Exception as e:
                logger.error(
                    "Collector %s failed: %s",
                    name, e,
                )
                errors.append(f"{name}: {e}")
        if errors:
            data["_collection_errors"] = errors
        return data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_iam(self) -> dict:
        """Collect IAM data only (global, not regional).

        Returns a dict that contains account metadata
        and the 'iam' key.  Suitable for merging into
        per-region results in a multi-region scan.
        """
        iam_collectors = [
            c for c in self.collectors
            if isinstance(c, IAMCollector)
        ]
        result = {
            "account_id": self.account_id,
            "collection_timestamp": (
                datetime.now(timezone.utc).isoformat()
            ),
        }
        result.update(
            self._run_collectors(iam_collectors)
        )
        return result

    def collect_regional(self) -> dict:
        """Collect all regional services (excludes IAM).

        Returns a dict that contains region metadata and
        all regional service keys (s3, ec2, vpc, …).
        Designed to be called once per region in a
        multi-region scan and then merged with IAM data.
        """
        regional_collectors = [
            c for c in self.collectors
            if not isinstance(c, IAMCollector)
        ]
        result = {
            "account_id": self.account_id,
            "region": self.region,
            "collection_timestamp": (
                datetime.now(timezone.utc).isoformat()
            ),
            "collection_mode": "regional",
        }
        result.update(
            self._run_collectors(regional_collectors)
        )
        return result

    def collect_full(self) -> dict:
        """Pull mode: full collection of all services.

        Returns the unified JSON document.
        Backward-compatible — behaviour unchanged.
        """
        unified = {
            "account_id": self.account_id,
            "region": self.region,
            "collection_timestamp": (
                datetime.now(timezone.utc).isoformat()
            ),
            "collection_mode": "full",
        }
        unified.update(
            self._run_collectors(self.collectors)
        )
        return unified

    def collect_targeted(
        self, service: str, resource_id: str
    ) -> dict:
        """Push mode: collect only the affected resource.

        Args:
            service: The AWS service name
                     (iam, s3, ec2, etc.)
            resource_id: The specific resource id.

        Returns:
            Dict with the resource's current state.
        """
        collector_cls = COLLECTOR_MAP.get(service)
        if not collector_cls:
            logger.error(
                "Unknown service: %s", service
            )
            return {}

        if collector_cls is EC2Collector:
            collector = collector_cls(
                self.session,
                self.account_id,
                self.region,
            )
        else:
            collector = collector_cls(self.session)
        return collector.collect_resource(
            resource_id
        )
