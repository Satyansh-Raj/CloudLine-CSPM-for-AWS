"""Resource inventory model for DynamoDB.

Defines the ResourceRecord used by the
resource-inventory table.
"""

from pydantic import BaseModel, Field


class ResourceRecord(BaseModel):
    """DynamoDB resource inventory record.

    Attributes:
        pk: Partition key ({account_id}#{region}).
        sk: Sort key ({resource_type}#{resource_id}).
        resource_id: AWS resource ARN.
        resource_name: Human-readable name.
        resource_type: Normalized type (s3_bucket, etc).
        technology_category: Category (compute, storage).
        service: AWS service name (s3, ec2, iam).
        region: AWS region.
        account_id: AWS account ID.
        exposure: Network exposure level.
        data_sensitivity: Data sensitivity level.
        data_types: Detected data type labels.
        environment: Deployment environment (from tags).
        owner: Resource owner (from tags).
        is_active: True if resource exists.
        tags: AWS resource tags.
        created_at: When first discovered.
        last_seen: Last scan timestamp.
        deactivated_at: When marked inactive.
        violation_count: Total violation count.
        critical_violations: Critical severity count.
        high_violations: High severity count.
        risk_score: Composite risk score (0-100).
        compliance_gaps: Compliance control gaps.
        connected_to: Related resource ARNs.
        managed_by: Managing IAM entity ARN.
        belongs_to: Parent resource ARN.

    Example:
        >>> r = ResourceRecord(
        ...     pk="123456789012#us-east-1",
        ...     sk="s3_bucket#arn:aws:s3:::my-bkt",
        ...     resource_id="arn:aws:s3:::my-bkt",
        ...     resource_name="my-bkt",
        ...     resource_type="s3_bucket",
        ...     technology_category="storage",
        ...     service="s3",
        ...     region="us-east-1",
        ...     account_id="123456789012",
        ...     last_seen="2026-03-18T10:00:00Z",
        ... )
    """

    # Keys
    pk: str
    sk: str

    # Identity
    resource_id: str
    resource_name: str
    resource_type: str
    technology_category: str
    service: str
    region: str
    account_id: str

    # Classification
    exposure: str = "unknown"
    data_sensitivity: str = "unknown"
    data_types: list[str] = Field(
        default_factory=list
    )
    environment: str = "unknown"
    owner: str = ""

    # State
    is_active: bool = True
    tags: dict = Field(default_factory=dict)
    created_at: str | None = None
    last_seen: str
    deactivated_at: str | None = None

    # Security posture
    violation_count: int = 0
    critical_violations: int = 0
    high_violations: int = 0
    risk_score: int = 0
    compliance_gaps: list[str] = Field(
        default_factory=list
    )

    # Relationships
    connected_to: list[str] = Field(
        default_factory=list
    )
    managed_by: str | None = None
    belongs_to: str | None = None
