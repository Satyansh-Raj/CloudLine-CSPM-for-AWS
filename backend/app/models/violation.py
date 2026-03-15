"""Violation and compliance result models."""

from pydantic import BaseModel, Field


class ComplianceMapping(BaseModel):
    cis_aws: list[str] = Field(
        default_factory=list
    )
    nist_800_53: list[str] = Field(
        default_factory=list
    )
    pci_dss: list[str] = Field(
        default_factory=list
    )
    hipaa: list[str] = Field(
        default_factory=list
    )
    soc2: list[str] = Field(
        default_factory=list
    )


class Violation(BaseModel):
    """Single policy evaluation result."""

    check_id: str
    status: str  # alarm | ok | error | skip
    severity: str = ""  # critical|high|medium|low
    reason: str = ""
    resource: str = ""
    domain: str = ""
    compliance: ComplianceMapping = Field(
        default_factory=ComplianceMapping
    )
    remediation_id: str = ""


class ComplianceScore(BaseModel):
    """Aggregated compliance score."""

    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    score_percent: float = 0.0
    by_domain: dict[str, dict] = Field(
        default_factory=dict
    )
    by_severity: dict[str, int] = Field(
        default_factory=dict
    )
