"""TargetAccount model for multi-account scanning.

Represents a target AWS account that CloudLine will
scan via STS AssumeRole.
"""

from pydantic import BaseModel, Field


class TargetAccount(BaseModel):
    """A target AWS account for cross-account scanning.

    DynamoDB keys:
        pk: Always "ACCOUNTS" (fixed partition).
        sk: account_id (unique sort key per account).

    Attributes:
        pk: Partition key — always "ACCOUNTS".
        sk: Sort key — the target AWS account ID.
        account_id: The 12-digit AWS account ID.
        account_name: Human-readable account label.
        role_arn: ARN of the cross-account IAM role
            (arn:aws:iam::TARGET:role/CloudLineScanner).
        external_id: Optional STS ExternalId for
            extra protection against confused deputy.
        regions: List of AWS regions to scan.
        is_active: Whether this account is enabled.
        added_at: ISO timestamp when account was added.
        last_scanned: ISO timestamp of last completed
            scan, or None if never scanned.

    Example:
        >>> acc = TargetAccount(
        ...     sk="111111111111",
        ...     account_id="111111111111",
        ...     account_name="Dev",
        ...     role_arn=(
        ...         "arn:aws:iam::111111111111"
        ...         ":role/CloudLineScanner"
        ...     ),
        ... )
    """

    pk: str = "ACCOUNTS"
    sk: str  # account_id
    account_id: str
    account_name: str
    role_arn: str
    external_id: str = ""
    regions: list[str] = Field(
        default_factory=lambda: ["us-east-1"]
    )
    is_active: bool = True
    added_at: str = ""
    last_scanned: str | None = None
