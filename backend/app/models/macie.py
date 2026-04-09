"""Pydantic models for AWS Macie findings.

These models represent the data contract for Macie
findings within CloudLine's unified input schema.

MacieFinding — a single Macie finding for an S3 object.
MacieData    — container for all findings collected in
               one account/region scan, including a
               by_bucket index for O(1) lookup during
               data classification.
"""

from pydantic import BaseModel, ConfigDict, Field


class _Flex(BaseModel):
    """Base that silently accepts extra fields."""

    model_config = ConfigDict(extra="allow")


class MacieFinding(_Flex):
    """A single AWS Macie sensitive-data finding.

    Attributes:
        finding_id: Macie-assigned UUID.
        type: Finding type string from Macie API
            (e.g. "SensitiveData:S3Object/Personal").
        bucket_name: Affected S3 bucket name.
        severity: Macie severity label
            (Low | Medium | High).
        category: Macie finding category
            (CLASSIFICATION | POLICY).
        count: Number of affected S3 objects.
        first_observed_at: ISO-8601 timestamp.
        last_observed_at: ISO-8601 timestamp or None.
        region: AWS region where the bucket lives.
        account_id: AWS account ID that owns the bucket.
    """

    finding_id: str
    type: str
    bucket_name: str
    severity: str
    category: str
    count: int
    first_observed_at: str
    last_observed_at: str | None = None
    region: str = ""
    account_id: str = ""
    detection_types: list[str] = Field(
        default_factory=list
    )


class MacieData(_Flex):
    """Container for Macie findings from one scan.

    Attributes:
        enabled: Whether Macie is active in this region.
        findings: Flat list of all MacieFinding objects.
        by_bucket: Maps bucket_name → list of finding_ids
            for O(1) lookup during data classification.
        summary: Aggregated counts (total, by_severity,
            by_category). Populated by MacieCollector.
    """

    enabled: bool = False
    findings: list[MacieFinding] = Field(
        default_factory=list
    )
    by_bucket: dict[str, list[str]] = Field(
        default_factory=dict
    )
    summary: dict = Field(default_factory=dict)
