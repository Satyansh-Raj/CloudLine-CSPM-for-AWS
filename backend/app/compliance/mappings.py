"""Dynamic compliance mapping registry.

Loads check_id → framework control mappings from an
external JSON config file.  Replaces the hardcoded
compliance dicts previously embedded in every Rego
rule result.

Typical usage::

    from app.compliance.mappings import get_registry

    registry = get_registry()
    mapping = registry.get("iam_root_mfa")
    # mapping.cis_aws == ["1.5"]
"""

import json
import logging
import os
from functools import lru_cache

from app.models.violation import ComplianceMapping

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "config",
    "check_compliance_mapping.json",
)

_EMPTY = ComplianceMapping()


class ComplianceMappingRegistry:
    """In-memory registry of check_id → compliance.

    Attributes:
        version: Config file version string.
    """

    def __init__(self, config_path: str | None = None):
        path = config_path or _DEFAULT_CONFIG
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Compliance config not found: {path}"
            )

        with open(path) as f:
            data = json.load(f)

        self.version: str = data.get("version", "")
        self._frameworks: list[str] = data.get(
            "frameworks", []
        )
        raw = data.get("mappings", {})
        self._mappings: dict[str, ComplianceMapping] = {}
        for check_id, mapping in raw.items():
            self._mappings[check_id] = ComplianceMapping(
                cis_aws=mapping.get("cis_aws", []),
                nist_800_53=mapping.get(
                    "nist_800_53", []
                ),
                pci_dss=mapping.get("pci_dss", []),
                hipaa=mapping.get("hipaa", []),
                soc2=mapping.get("soc2", []),
                owasp=mapping.get("owasp", []),
            )

        logger.info(
            "Loaded %d compliance mappings (v%s)",
            len(self._mappings),
            self.version,
        )

    def get(self, check_id: str) -> ComplianceMapping:
        """Look up compliance for a check_id.

        Returns an empty ComplianceMapping if the
        check_id is not in the registry.
        """
        return self._mappings.get(check_id, _EMPTY)

    def contains(self, check_id: str) -> bool:
        """Check if a check_id exists."""
        return check_id in self._mappings

    def check_ids(self) -> list[str]:
        """Return all registered check_ids."""
        return list(self._mappings.keys())

    def frameworks(self) -> list[str]:
        """Return the list of supported frameworks."""
        return list(self._frameworks)

    def check_ids_for_framework(
        self, framework: str
    ) -> list[str]:
        """Return all check_ids that map to a framework.

        A check_id is included when the framework
        attribute on its ComplianceMapping is a
        non-empty list.

        Args:
            framework: One of the supported framework
                names (e.g. 'cis_aws', 'nist_800_53').

        Returns:
            List of check_ids that have at least one
            control mapped to the given framework.
            Returns [] for unknown frameworks.
        """
        result: list[str] = []
        for check_id, mapping in self._mappings.items():
            controls = getattr(mapping, framework, None)
            if controls:
                result.append(check_id)
        return result


def enrich_compliance(
    violations: list,
    registry: "ComplianceMappingRegistry | None" = None,
) -> list:
    """Attach compliance mappings to violations.

    Looks up each violation's check_id in the
    registry and overwrites its compliance field
    with the authoritative mapping.

    Args:
        violations: List of Violation objects.
        registry: Optional registry override.

    Returns:
        The same list (mutated in place).
    """
    reg = registry or get_registry()
    for v in violations:
        v.compliance = reg.get(v.check_id)
    return violations


@lru_cache(maxsize=1)
def get_registry(
    config_path: str | None = None,
) -> ComplianceMappingRegistry:
    """Return a cached singleton registry.

    Args:
        config_path: Override config file path.

    Returns:
        The global ComplianceMappingRegistry.
    """
    return ComplianceMappingRegistry(config_path)
