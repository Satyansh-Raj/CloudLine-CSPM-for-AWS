"""Parses OPA JSON output into Violation models."""

import logging

from app.models.violation import (
    ComplianceMapping,
    Violation,
)

logger = logging.getLogger(__name__)


class ResultParser:
    """Converts raw OPA result dicts into Violation
    Pydantic models."""

    def parse(
        self, raw: dict
    ) -> Violation | None:
        """Parse a single OPA result dict.

        Args:
            raw: Dict matching the standard result
                 schema from Rego policies.

        Returns:
            A Violation model, or None if invalid.
        """
        if not isinstance(raw, dict):
            logger.warning(
                "Expected dict, got %s",
                type(raw),
            )
            return None

        check_id = raw.get("check_id", "")
        if not check_id:
            logger.warning(
                "Result missing check_id: %s",
                raw,
            )
            return None

        compliance_raw = raw.get(
            "compliance", {}
        )
        compliance = ComplianceMapping(
            cis_aws=compliance_raw.get(
                "cis_aws", []
            ),
            nist_800_53=compliance_raw.get(
                "nist_800_53", []
            ),
            pci_dss=compliance_raw.get(
                "pci_dss", []
            ),
            hipaa=compliance_raw.get(
                "hipaa", []
            ),
            soc2=compliance_raw.get("soc2", []),
        )

        return Violation(
            check_id=check_id,
            status=raw.get("status", "error"),
            severity=raw.get("severity", ""),
            reason=raw.get("reason", ""),
            resource=raw.get("resource", ""),
            domain=raw.get("domain", ""),
            compliance=compliance,
            remediation_id=raw.get(
                "remediation_id", ""
            ),
        )
