"""Compliance mapper — maps DataClassification to
compliance frameworks, controls, and requirement gaps.

Loads mapping data from a JSON config file so rules are
auditable and editable without code changes.

The default config is:
  backend/config/compliance_mapping.json

resolved relative to this source file's location.
"""

import json
import logging
from pathlib import Path

from pydantic import BaseModel

from app.inventory.data_classifier import DataClassification

logger = logging.getLogger(__name__)

# Default config path: two levels up from this file
# (app/inventory/ → app/ → backend/) then into config/
_DEFAULT_CONFIG = (
    Path(__file__).parent.parent.parent
    / "config"
    / "compliance_mapping.json"
)


class ComplianceRequirement(BaseModel):
    """A single framework's controls and requirements.

    Attributes:
        framework: Display name e.g. "PCI DSS".
        controls: List of control IDs e.g. ["3.4"].
        requirements: Human-readable requirement strings.
    """

    framework: str
    controls: list[str]
    requirements: list[str]


class DataComplianceResult(BaseModel):
    """Full compliance mapping result for a resource.

    Attributes:
        data_types: Detected data type labels.
        sensitivity: Highest sensitivity level.
        frameworks: Deduplicated framework names.
        compliance_requirements: Per-framework detail.
        compliance_gaps: "FRAMEWORK CONTROL" strings.
    """

    data_types: list[str]
    sensitivity: str
    frameworks: list[str]
    compliance_requirements: list[ComplianceRequirement]
    compliance_gaps: list[str]


class ComplianceMapper:
    """Maps DataClassification to compliance results.

    Loads a JSON config file on init. The default path
    is ``backend/config/compliance_mapping.json``,
    resolved relative to this source file.

    Attributes:
        config_path: Absolute path to the JSON config.
    """

    def __init__(
        self, config_path: str | None = None
    ) -> None:
        self.config_path: Path = (
            Path(config_path)
            if config_path is not None
            else _DEFAULT_CONFIG
        )
        self._config: dict = {}
        self._load()

    # ── Private helpers ────────────────────────────

    def _load(self) -> None:
        """Read and parse the JSON config from disk.

        Raises:
            FileNotFoundError: If the path does not exist.
        """
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Compliance mapping config not found: "
                f"{self.config_path}"
            )
        with self.config_path.open(
            encoding="utf-8"
        ) as fh:
            self._config = json.load(fh)

    def _framework_name(self, key: str) -> str:
        """Resolve a framework_key to display name."""
        names: dict[str, str] = self._config.get(
            "framework_names", {}
        )
        return names.get(key, key)

    # ── Public API ─────────────────────────────────

    def map(
        self,
        classification: DataClassification,
    ) -> DataComplianceResult:
        """Map a DataClassification to compliance result.

        For each data_type in classification.data_types:
          - Look up the mapping entry in the JSON config
          - Collect frameworks, controls, requirements

        Frameworks and gap strings are deduplicated.
        Unknown data types are silently skipped.

        Args:
            classification: Output of DataClassifier.

        Returns:
            DataComplianceResult with frameworks,
            controls, requirements, and gaps.
        """
        mappings: dict = self._config.get(
            "mappings", {}
        )

        # Accumulate per-framework data across all types.
        # Key: framework_key, Value: mapping entry dict
        seen_fw_keys: dict[str, dict] = {}

        for dtype in classification.data_types:
            entry = mappings.get(dtype)
            if entry is None:
                continue
            controls: dict[str, list[str]] = (
                entry.get("controls", {})
            )
            for fw_key, ctrls in controls.items():
                if fw_key not in seen_fw_keys:
                    seen_fw_keys[fw_key] = {
                        "controls": list(ctrls),
                        "requirements": list(
                            entry.get("requirements", [])
                        ),
                    }
                else:
                    # Merge controls (deduplicate)
                    existing = seen_fw_keys[fw_key][
                        "controls"
                    ]
                    for c in ctrls:
                        if c not in existing:
                            existing.append(c)
                    # Merge requirements (deduplicate)
                    existing_req = seen_fw_keys[fw_key][
                        "requirements"
                    ]
                    for req in entry.get(
                        "requirements", []
                    ):
                        if req not in existing_req:
                            existing_req.append(req)

        if not seen_fw_keys:
            return DataComplianceResult(
                data_types=classification.data_types,
                sensitivity=classification.sensitivity,
                frameworks=[],
                compliance_requirements=[],
                compliance_gaps=[],
            )

        # Build ComplianceRequirement list and gap strings
        requirements: list[ComplianceRequirement] = []
        gaps: list[str] = []
        frameworks: list[str] = []

        for fw_key, data in seen_fw_keys.items():
            display = self._framework_name(fw_key)
            if display not in frameworks:
                frameworks.append(display)
            requirements.append(
                ComplianceRequirement(
                    framework=display,
                    controls=data["controls"],
                    requirements=data["requirements"],
                )
            )
            for ctrl in data["controls"]:
                gap = f"{display} {ctrl}"
                if gap not in gaps:
                    gaps.append(gap)

        return DataComplianceResult(
            data_types=classification.data_types,
            sensitivity=classification.sensitivity,
            frameworks=frameworks,
            compliance_requirements=requirements,
            compliance_gaps=gaps,
        )

    def reload(self) -> None:
        """Re-read the JSON config from disk.

        Useful for picking up live config changes without
        restarting the process.
        """
        self._load()
