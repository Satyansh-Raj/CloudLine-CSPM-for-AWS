"""Collection orchestrator — runs all collectors and
merges results into the unified JSON document."""

import logging
from datetime import datetime, timezone

import boto3

from app.collectors.ec2 import EC2Collector
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

# Maps service names to collector classes
COLLECTOR_MAP = {
    "iam": IAMCollector,
    "s3": S3Collector,
    "ec2": EC2Collector,
    "vpc": VPCCollector,
    "rds": RDSCollector,
    "lambda": LambdaCollector,
    "logging": LoggingCollector,
    "kms": KMSCollector,
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

    def collect_full(self) -> dict:
        """Pull mode: full collection of all services.

        Returns the unified JSON document.
        """
        unified = {
            "account_id": self.account_id,
            "region": self.region,
            "collection_timestamp": (
                datetime.now(timezone.utc).isoformat()
            ),
            "collection_mode": "full",
        }
        errors: list[str] = []

        for collector in self.collectors:
            name = collector.__class__.__name__
            try:
                if isinstance(
                    collector, KMSCollector
                ):
                    # Use collect_full to get kms,
                    # secrets_manager, and backup
                    # in a single round-trip.
                    extra = collector.collect_full()
                    unified["kms"] = extra.get(
                        "kms", {"keys": []}
                    )
                    unified[
                        "secrets_manager"
                    ] = extra.get(
                        "secrets_manager",
                        {"secrets": []},
                    )
                    unified["backup"] = extra.get(
                        "backup",
                        {
                            "plans": [],
                            "protected_resources": [],
                        },
                    )
                else:
                    key, data = collector.collect()
                    unified[key] = data
            except Exception as e:
                logger.error(
                    "Collector %s failed: %s",
                    name, e,
                )
                errors.append(
                    f"{name}: {e}"
                )

        if errors:
            unified["_collection_errors"] = errors

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
