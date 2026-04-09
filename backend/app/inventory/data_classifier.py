"""Data type detection engine for CloudLine.

Detects what kind of data is stored in AWS resources
using three signal sources:
  1. S3 object key sampling (extension/prefix patterns)
  2. AWS Macie findings ingestion
  3. RDS/DynamoDB schema/metadata extraction

Returns a DataClassification for each resource.
"""

import logging

import boto3
import botocore.exceptions
from pydantic import BaseModel

from app.models.macie import MacieData

logger = logging.getLogger(__name__)

# ── Signal word lists ──────────────────────────────

PII_SIGNALS: list[str] = [
    "customer",
    "user",
    "personal",
    "pii",
    "ssn",
    "passport",
    "email",
    "phone",
    "address",
    "identity",
    "profile",
]

FINANCIAL_SIGNALS: list[str] = [
    "payment",
    "invoice",
    "billing",
    "transaction",
    "financial",
    "account_balance",
    "account",
    "revenue",
    "invoice",
    "credit",
    "debit",
]

HEALTH_SIGNALS: list[str] = [
    "health",
    "medical",
    "patient",
    "hipaa",
    "phi",
    "ehr",
    "clinical",
    "prescription",
    "diagnosis",
]

CREDENTIAL_SIGNALS: list[str] = [
    "secret",
    "credential",
    "key",
    "token",
    "password",
    ".env",
    "private",
    "cert",
    "auth",
]

LOG_SIGNALS: list[str] = [
    "log",
    "audit",
    "trail",
    "event",
    "access_log",
    "cloudwatch",
]

# Maps data type → sensitivity level
_SENSITIVITY_MAP: dict[str, str] = {
    "pii": "critical",
    "health": "critical",
    "financial": "high",
    "credentials": "high",
    "analytics": "medium",
    "media": "medium",
    "logs": "low",
    "config": "low",
    "backups": "low",
}

# Ordered from highest to lowest sensitivity
_SENSITIVITY_ORDER: list[str] = [
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
]

# Tag key → {tag_value → data_type}
TAG_MAPPINGS: dict[str, dict[str, str]] = {
    "data-classification": {
        "pii": "pii",
        "confidential": "pii",
        "public": "config",
        "financial": "financial",
        "health": "health",
        "credentials": "credentials",
        "logs": "logs",
        "config": "config",
    },
    "compliance": {
        "hipaa": "health",
        "pci": "financial",
        "pci-dss": "financial",
    },
}

# Macie finding type substring → data_type
_MACIE_TYPE_MAP: dict[str, str] = {
    "Personal": "pii",
    "Financial": "financial",
    "Credentials": "credentials",
    "CustomIdentifier": "pii",
    "Multiple": "pii",
}


# ── DataClassification model ───────────────────────


class DataClassification(BaseModel):
    """Result of data type detection.

    Attributes:
        sensitivity: critical|high|medium|low|unknown.
        data_types: Detected labels e.g. ["pii"].
        confidence: high|medium|low.
        source: tag|macie|heuristic|schema.
    """

    sensitivity: str
    data_types: list[str]
    confidence: str
    source: str


# ── Helpers ────────────────────────────────────────


def _unknown() -> DataClassification:
    """Return a default unknown classification."""
    return DataClassification(
        sensitivity="unknown",
        data_types=[],
        confidence="low",
        source="heuristic",
    )


def _signals_match(
    text: str, signals: list[str]
) -> bool:
    """Return True if any signal appears in text."""
    lower = text.lower()
    return any(sig in lower for sig in signals)


def _detect_types_from_text(
    text: str,
) -> list[str]:
    """Return all data type labels signalled by text."""
    types: list[str] = []
    if _signals_match(text, PII_SIGNALS):
        types.append("pii")
    if _signals_match(text, FINANCIAL_SIGNALS):
        types.append("financial")
    if _signals_match(text, HEALTH_SIGNALS):
        types.append("health")
    if _signals_match(text, CREDENTIAL_SIGNALS):
        types.append("credentials")
    if _signals_match(text, LOG_SIGNALS):
        types.append("logs")
    return types


def _merge_types(
    type_lists: list[list[str]],
) -> list[str]:
    """Deduplicate across multiple type lists."""
    seen: set[str] = set()
    merged: list[str] = []
    for lst in type_lists:
        for t in lst:
            if t not in seen:
                seen.add(t)
                merged.append(t)
    return merged


def _highest_sensitivity(
    data_types: list[str],
) -> str:
    """Return the highest sensitivity across types."""
    levels = [
        _SENSITIVITY_MAP.get(t, "unknown")
        for t in data_types
    ]
    for level in _SENSITIVITY_ORDER:
        if level in levels:
            return level
    return "unknown"


def _classify_from_tags(
    tags: dict,
) -> DataClassification | None:
    """Try tag-based classification (highest confidence).

    Returns DataClassification if a matching tag is found,
    otherwise None.
    """
    lower_tags = {
        k.lower(): v.lower()
        for k, v in tags.items()
    }
    found_types: list[str] = []

    for tag_key, value_map in TAG_MAPPINGS.items():
        if tag_key in lower_tags:
            val = lower_tags[tag_key]
            if val in value_map:
                dt = value_map[val]
                if dt not in found_types:
                    found_types.append(dt)

    if not found_types:
        return None

    sensitivity = _highest_sensitivity(found_types)
    return DataClassification(
        sensitivity=sensitivity,
        data_types=found_types,
        confidence="high",
        source="tag",
    )


def _classify_from_macie_data(
    bucket_name: str,
    macie_data: MacieData,
) -> DataClassification | None:
    """Classify an S3 bucket using pre-collected Macie data.

    Looks up the bucket in macie_data.by_bucket, fetches
    the relevant MacieFinding objects, and maps finding
    types to data_type labels via _MACIE_TYPE_MAP.

    Args:
        bucket_name: S3 bucket name to look up.
        macie_data: Pre-collected MacieData from
            MacieCollector.

    Returns:
        DataClassification(source="macie") if findings
        exist for this bucket, otherwise None.
    """
    finding_ids = set(
        macie_data.by_bucket.get(bucket_name, [])
    )
    if not finding_ids:
        return None

    findings = [
        f
        for f in macie_data.findings
        if f.finding_id in finding_ids
    ]

    found_types: list[str] = []
    for f in findings:
        for keyword, dt in _MACIE_TYPE_MAP.items():
            if keyword in f.type:
                if dt not in found_types:
                    found_types.append(dt)
                break

    if not found_types:
        return None

    sensitivity = _highest_sensitivity(found_types)
    return DataClassification(
        sensitivity=sensitivity,
        data_types=found_types,
        confidence="high",
        source="macie",
    )


# ── DataClassifier ─────────────────────────────────


class DataClassifier:
    """Detects data types stored in AWS resources.

    Attributes:
        session: Authenticated boto3 Session.
    """

    def __init__(self, session: boto3.Session):
        self.session = session

    # ── S3 ─────────────────────────────────────────

    def classify_s3_bucket(
        self,
        bucket_name: str,
        tags: dict,
        macie_data: MacieData | None = None,
    ) -> DataClassification:
        """Classify an S3 bucket using a 3-tier priority.

        Priority order (highest → lowest confidence):
          1. Pre-collected Macie findings (source=macie)
          2. AWS resource tags (source=tag)
          3. S3 object key sampling (source=heuristic)

        Args:
            bucket_name: S3 bucket name.
            tags: AWS resource tags dict.
            macie_data: Pre-collected MacieData from
                MacieCollector. When provided and enabled,
                Macie findings take precedence over tags.

        Returns:
            DataClassification for this bucket.
        """
        # 1. Macie (highest confidence)
        if macie_data is not None and macie_data.enabled:
            macie_result = _classify_from_macie_data(
                bucket_name, macie_data
            )
            if macie_result is not None:
                return macie_result

        # 2. Tag-based check (high confidence)
        tag_result = _classify_from_tags(tags)
        if tag_result is not None:
            return tag_result

        # Sample object keys
        keys = self._list_s3_keys(bucket_name)
        if not keys:
            return _unknown()

        all_types: list[list[str]] = []
        for key in keys:
            detected = _detect_types_from_text(key)
            if detected:
                all_types.append(detected)

        merged = _merge_types(all_types)
        if not merged:
            return _unknown()

        sensitivity = _highest_sensitivity(merged)
        return DataClassification(
            sensitivity=sensitivity,
            data_types=merged,
            confidence="medium",
            source="heuristic",
        )

    def _list_s3_keys(
        self, bucket_name: str
    ) -> list[str]:
        """Sample up to 100 S3 object keys.

        Returns empty list on any error.
        """
        try:
            s3 = self.session.client(
                "s3", region_name=None
            )
            resp = s3.list_objects_v2(
                Bucket=bucket_name,
                MaxKeys=100,
            )
            contents = resp.get("Contents", [])
            return [obj["Key"] for obj in contents]
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            logger.warning(
                "S3 ListObjectsV2 failed (%s) "
                "for bucket %s: %s",
                code,
                bucket_name,
                e,
            )
            return []
        except Exception as e:
            logger.error(
                "S3 key sampling error for %s: %s",
                bucket_name,
                e,
            )
            return []

    # ── Macie ──────────────────────────────────────

    def classify_from_macie(
        self,
        bucket_name: str,
    ) -> DataClassification | None:
        """Ingest Macie findings for an S3 bucket.

        Args:
            bucket_name: S3 bucket name to filter on.

        Returns:
            DataClassification if findings exist,
            None if Macie is disabled or no findings.
        """
        try:
            macie = self.session.client("macie2")
            resp = macie.list_findings(
                findingCriteria={
                    "criterion": {
                        "resourcesAffected"
                        ".s3Bucket.name": {
                            "eq": [bucket_name]
                        }
                    }
                }
            )
            ids = resp.get("findingIds", [])
            if not ids:
                return None

            details = macie.get_findings(
                findingIds=ids
            )
            findings = details.get("findings", [])

            found_types: list[str] = []
            for f in findings:
                ftype = f.get("type", "")
                for keyword, dt in (
                    _MACIE_TYPE_MAP.items()
                ):
                    if keyword in ftype:
                        if dt not in found_types:
                            found_types.append(dt)
                        break

            if not found_types:
                return None

            sensitivity = _highest_sensitivity(
                found_types
            )
            return DataClassification(
                sensitivity=sensitivity,
                data_types=found_types,
                confidence="high",
                source="macie",
            )

        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            logger.warning(
                "Macie unavailable (%s): %s",
                code,
                e,
            )
            return None
        except Exception as e:
            logger.error(
                "Macie classification error "
                "for %s: %s",
                bucket_name,
                e,
            )
            return None

    # ── RDS ────────────────────────────────────────

    def classify_rds_instance(
        self,
        db_id: str,
        engine: str,
        tags: dict,
    ) -> DataClassification:
        """Classify an RDS instance by name/engine/tags.

        Args:
            db_id: DB instance identifier.
            engine: Database engine name.
            tags: AWS resource tags dict.

        Returns:
            DataClassification for this instance.
        """
        # Tag-based check (highest confidence)
        tag_result = _classify_from_tags(tags)
        if tag_result is not None:
            return tag_result

        # Name-based heuristic
        combined = f"{db_id} {engine}"
        detected = _detect_types_from_text(combined)
        if not detected:
            return _unknown()

        sensitivity = _highest_sensitivity(detected)
        return DataClassification(
            sensitivity=sensitivity,
            data_types=detected,
            confidence="medium",
            source="heuristic",
        )

    # ── DynamoDB ───────────────────────────────────

    def classify_dynamodb_table(
        self,
        table_name: str,
        tags: dict,
    ) -> DataClassification:
        """Classify a DynamoDB table by field names.

        Performs a Scan(Limit=1) to inspect field names,
        then applies heuristic patterns. Falls back to
        table name heuristics on AccessDenied.

        Args:
            table_name: DynamoDB table name.
            tags: AWS resource tags dict.

        Returns:
            DataClassification for this table.
        """
        # Tag-based check (highest confidence)
        tag_result = _classify_from_tags(tags)
        if tag_result is not None:
            return tag_result

        # Sample one item for field names
        field_types = self._scan_dynamodb_fields(
            table_name
        )

        if field_types:
            sensitivity = _highest_sensitivity(
                field_types
            )
            return DataClassification(
                sensitivity=sensitivity,
                data_types=field_types,
                confidence="medium",
                source="schema",
            )

        # Fall back to table name heuristics
        name_types = _detect_types_from_text(
            table_name
        )
        if name_types:
            sensitivity = _highest_sensitivity(
                name_types
            )
            return DataClassification(
                sensitivity=sensitivity,
                data_types=name_types,
                confidence="medium",
                source="heuristic",
            )

        return _unknown()

    def _scan_dynamodb_fields(
        self, table_name: str
    ) -> list[str]:
        """Scan one item to extract field-name signals.

        Returns list of detected data types, or empty list
        on error or when no items exist.
        """
        try:
            ddb = self.session.client("dynamodb")
            resp = ddb.scan(
                TableName=table_name, Limit=1
            )
            items = resp.get("Items", [])
            if not items:
                return []

            # Collect all field names from first item
            fields = " ".join(items[0].keys())
            return _detect_types_from_text(fields)

        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            logger.warning(
                "DynamoDB Scan failed (%s) "
                "for table %s: %s",
                code,
                table_name,
                e,
            )
            return []
        except Exception as e:
            logger.error(
                "DynamoDB field scan error "
                "for %s: %s",
                table_name,
                e,
            )
            return []

    # ── Dispatcher ─────────────────────────────────

    def classify_resource(
        self,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        tags: dict,
        macie_data: MacieData | None = None,
    ) -> DataClassification:
        """Dispatch to the correct classifier method.

        Supported resource types:
          - s3_bucket
          - rds_instance
          - dynamodb_table

        All other types return unknown classification.

        Args:
            resource_type: Normalized type (s3_bucket etc).
            resource_id: AWS resource ARN.
            resource_name: Human-readable name.
            tags: AWS resource tags dict.
            macie_data: Pre-collected MacieData from
                MacieCollector (used for S3 buckets only).

        Returns:
            DataClassification for this resource.
        """
        if resource_type == "s3_bucket":
            return self.classify_s3_bucket(
                resource_name, tags, macie_data
            )
        if resource_type == "rds_instance":
            return self.classify_rds_instance(
                resource_name, "", tags
            )
        if resource_type == "dynamodb_table":
            return self.classify_dynamodb_table(
                resource_name, tags
            )
        return _unknown()
