"""Contextual risk scoring engine (Phase 4).

Computes a 5-dimensional risk score for each violation:
severity, exploitability, blast_radius, data_sensitivity,
compliance_impact. Weighted composite yields 0-100 score.
"""

import logging

from pydantic import BaseModel

from app.models.violation import ComplianceMapping

logger = logging.getLogger(__name__)

WEIGHTS = {
    "severity": 0.30,
    "exploitability": 0.25,
    "blast_radius": 0.20,
    "data_sensitivity": 0.15,
    "compliance_impact": 0.10,
}

SEVERITY_MAP = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
}

FRAMEWORK_WEIGHTS = {
    "cis_aws": 25,
    "nist_800_53": 25,
    "pci_dss": 20,
    "hipaa": 20,
    "soc2": 10,
}

# Exploitability scores by service + condition
_EXPLOIT_S3 = {
    "full_public": 100,
    "wildcard_principal": 90,
    "partial_public": 50,
}

_EXPLOIT_EC2 = {
    "open_cidr": 100,
    "public_ip": 80,
    "imdsv1": 60,
}

_EXPLOIT_IAM = {
    "unused_key": 70,
    "no_mfa": 60,
}

_EXPLOIT_RDS = {
    "publicly_accessible": 100,
    "no_encryption": 60,
}

_EXPLOIT_LAMBDA = {
    "public_policy": 80,
}

DEFAULT_EXPLOITABILITY = 20

# Blast radius scores by service + signal
_BLAST_IAM = {
    "admin_policy": 100,
    "many_entities": 80,
    "some_entities": 60,
}

_BLAST_EC2 = {
    "many_instances": 80,
    "some_instances": 40,
}

_BLAST_OTHER = {
    "s3": 50,
    "rds_multi_az": 60,
    "rds_single": 30,
    "lambda": 20,
    "logging": 90,
}

DEFAULT_BLAST_RADIUS = 30

# Data sensitivity tag-value mapping
_SENSITIVITY_MAP = {
    "pii": 100,
    "personally-identifiable": 100,
    "phi": 90,
    "protected-health": 90,
    "financial": 80,
    "payment": 80,
    "pci": 80,
    "confidential": 70,
    "internal": 40,
    "public": 10,
}

_SENSITIVITY_TAG_KEYS = {
    "data-classification",
    "dataclassification",
    "data_classification",
    "sensitivity",
}

DEFAULT_DATA_SENSITIVITY = 20


class RiskDimensions(BaseModel):
    """Five-dimensional risk score result.

    Attributes:
        severity: Severity dimension (0-100).
        exploitability: Exploitability dimension.
        blast_radius: Blast radius dimension.
        data_sensitivity: Data sensitivity dimension.
        compliance_impact: Compliance impact dimension.
        composite: Weighted composite score (0-100).
        category: Risk category string.
    """

    severity: int = 0
    exploitability: int = 0
    blast_radius: int = 0
    data_sensitivity: int = 0
    compliance_impact: int = 0
    composite: int = 0
    category: str = "low"


class RiskScorer:
    """Computes contextual risk scores for violations.

    Uses a 5-dimensional model with configurable weights
    to produce a composite 0-100 risk score.

    Example:
        >>> scorer = RiskScorer()
        >>> dims = scorer.score(
        ...     violation=violation_obj,
        ...     resource_data={"Tags": []},
        ...     service="s3",
        ... )
        >>> dims.composite
        42
    """

    def score(
        self,
        violation,
        resource_data: dict,
        service: str,
    ) -> RiskDimensions:
        """Compute all 5 dimensions and composite score.

        Args:
            violation: Violation model or None.
            resource_data: Raw AWS resource data dict.
            service: AWS service name (s3, ec2, etc).

        Returns:
            RiskDimensions with all scores populated.
        """
        if violation is None:
            return RiskDimensions()

        sev = self.compute_severity(
            getattr(violation, "severity", "")
        )
        compliance = getattr(
            violation, "compliance", None
        )
        comp_impact = self.compute_compliance_impact(
            compliance
        )
        exploit = self.compute_exploitability(
            resource_data, service
        )
        blast = self.compute_blast_radius(
            resource_data, service
        )
        data_sens = self.compute_data_sensitivity(
            resource_data
        )

        dims = RiskDimensions(
            severity=sev,
            exploitability=exploit,
            blast_radius=blast,
            data_sensitivity=data_sens,
            compliance_impact=comp_impact,
        )
        dims.composite = self._compute_composite(dims)
        dims.category = self.categorize(
            dims.composite
        )
        return dims

    def compute_severity(self, severity: str) -> int:
        """Map severity string to 0-100 score.

        Args:
            severity: Severity level string.

        Returns:
            Integer score (0-100).

        Example:
            >>> RiskScorer().compute_severity("critical")
            100
        """
        if not severity:
            return 0
        return SEVERITY_MAP.get(severity.lower(), 0)

    def compute_compliance_impact(
        self,
        compliance: ComplianceMapping | None,
    ) -> int:
        """Score based on compliance framework coverage.

        Sums FRAMEWORK_WEIGHTS for each framework that
        has at least one control listed. Capped at 100.

        Args:
            compliance: ComplianceMapping model or None.

        Returns:
            Integer score (0-100).

        Example:
            >>> from app.models.violation import (
            ...     ComplianceMapping,
            ... )
            >>> c = ComplianceMapping(
            ...     cis_aws=["2.1.1"],
            ...     pci_dss=["3.4"],
            ... )
            >>> RiskScorer().compute_compliance_impact(c)
            45
        """
        if compliance is None:
            return 0

        total = 0
        for framework, weight in (
            FRAMEWORK_WEIGHTS.items()
        ):
            controls = getattr(
                compliance, framework, []
            )
            if controls:
                total += weight

        return min(total, 100)

    def compute_exploitability(
        self,
        resource_data: dict,
        service: str,
    ) -> int:
        """Score exploitability based on resource config.

        Evaluates service-specific conditions and returns
        the highest matching score.

        Args:
            resource_data: Raw AWS resource data.
            service: AWS service name.

        Returns:
            Integer score (0-100).
        """
        if not resource_data:
            return DEFAULT_EXPLOITABILITY

        service_lower = service.lower()

        if service_lower == "s3":
            return self._exploit_s3(resource_data)
        if service_lower == "ec2":
            return self._exploit_ec2(resource_data)
        if service_lower == "iam":
            return self._exploit_iam(resource_data)
        if service_lower == "rds":
            return self._exploit_rds(resource_data)
        if service_lower == "lambda":
            return self._exploit_lambda(resource_data)

        return DEFAULT_EXPLOITABILITY

    def compute_blast_radius(
        self,
        resource_data: dict,
        service: str,
    ) -> int:
        """Score blast radius based on resource scope.

        Args:
            resource_data: Raw AWS resource data.
            service: AWS service name.

        Returns:
            Integer score (0-100).
        """
        if not resource_data:
            return DEFAULT_BLAST_RADIUS

        service_lower = service.lower()

        if service_lower == "iam":
            return self._blast_iam(resource_data)
        if service_lower == "ec2":
            return self._blast_ec2(resource_data)
        if service_lower == "s3":
            return _BLAST_OTHER["s3"]
        if service_lower == "rds":
            return self._blast_rds(resource_data)
        if service_lower == "lambda":
            return _BLAST_OTHER["lambda"]
        if service_lower in (
            "cloudtrail",
            "cloudwatch",
            "config",
        ):
            return _BLAST_OTHER["logging"]

        return DEFAULT_BLAST_RADIUS

    def compute_data_sensitivity(
        self, resource_data: dict
    ) -> int:
        """Score data sensitivity from resource tags.

        Searches resource_data recursively for Tags/tags
        arrays with AWS Key/Value pairs. Looks for
        classification tag keys and maps values.

        Args:
            resource_data: Raw AWS resource data.

        Returns:
            Integer score (0-100).
        """
        if not resource_data:
            return DEFAULT_DATA_SENSITIVITY

        tags = _extract_tags(resource_data)
        if not tags:
            return DEFAULT_DATA_SENSITIVITY

        for key, value in tags.items():
            if key.lower() in _SENSITIVITY_TAG_KEYS:
                val_lower = value.lower()
                if val_lower in _SENSITIVITY_MAP:
                    return _SENSITIVITY_MAP[val_lower]

        return DEFAULT_DATA_SENSITIVITY

    def _compute_composite(
        self, dims: RiskDimensions
    ) -> int:
        """Weighted sum of all 5 dimensions.

        Args:
            dims: RiskDimensions with individual scores.

        Returns:
            Rounded integer composite (0-100).
        """
        raw = (
            dims.severity * WEIGHTS["severity"]
            + dims.exploitability
            * WEIGHTS["exploitability"]
            + dims.blast_radius
            * WEIGHTS["blast_radius"]
            + dims.data_sensitivity
            * WEIGHTS["data_sensitivity"]
            + dims.compliance_impact
            * WEIGHTS["compliance_impact"]
        )
        return round(raw)

    def categorize(self, score: int) -> str:
        """Map composite score to category.

        Args:
            score: Composite score (0-100).

        Returns:
            Category string.

        Example:
            >>> RiskScorer().categorize(95)
            'critical'
        """
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    # -- Service-specific exploitability helpers --

    def _exploit_s3(self, data: dict) -> int:
        """S3 exploitability scoring."""
        scores = []

        # Check public access block config
        pab = data.get(
            "public_access_block",
            data.get(
                "PublicAccessBlockConfiguration",
                {},
            ),
        )
        if pab:
            pab_keys = (
                "block_public_acls",
                "ignore_public_acls",
                "block_public_policy",
                "restrict_public_buckets",
            )
            all_disabled = all(
                not pab.get(k, True)
                for k in pab_keys
            )
            if all_disabled:
                scores.append(
                    _EXPLOIT_S3["full_public"]
                )
            elif any(
                not pab.get(k, True)
                for k in pab_keys
            ):
                scores.append(
                    _EXPLOIT_S3["partial_public"]
                )

        # Check bucket policy for wildcard
        policy = data.get(
            "policy",
            data.get("Policy", {}),
        )
        statements = policy.get(
            "Statement", []
        )
        for stmt in statements:
            principal = stmt.get(
                "Principal", ""
            )
            if principal == "*" or (
                isinstance(principal, dict)
                and principal.get("AWS") == "*"
            ):
                scores.append(
                    _EXPLOIT_S3[
                        "wildcard_principal"
                    ]
                )
                break

        return max(scores) if scores else (
            DEFAULT_EXPLOITABILITY
        )

    def _exploit_ec2(self, data: dict) -> int:
        """EC2 exploitability scoring."""
        scores = []

        # Check SG ingress for open CIDR
        ingress = data.get(
            "ingress_rules",
            data.get("IpPermissions", []),
        )
        if isinstance(ingress, list):
            for rule in ingress:
                cidr = rule.get(
                    "cidr",
                    rule.get("CidrIp", ""),
                )
                if cidr in (
                    "0.0.0.0/0",
                    "::/0",
                ):
                    scores.append(
                        _EXPLOIT_EC2["open_cidr"]
                    )

        # Check for public IP
        if data.get(
            "public_ip"
        ) or data.get("PublicIpAddress"):
            scores.append(
                _EXPLOIT_EC2["public_ip"]
            )

        # Check IMDSv1
        metadata = data.get(
            "metadata_options",
            data.get("MetadataOptions", {}),
        )
        if metadata:
            tokens = metadata.get(
                "http_tokens",
                metadata.get(
                    "HttpTokens", "optional"
                ),
            )
            if tokens != "required":
                scores.append(
                    _EXPLOIT_EC2["imdsv1"]
                )

        return max(scores) if scores else (
            DEFAULT_EXPLOITABILITY
        )

    def _exploit_iam(self, data: dict) -> int:
        """IAM exploitability scoring."""
        scores = []

        # Access key with no recent usage
        keys = data.get(
            "access_keys",
            data.get("AccessKeys", []),
        )
        for key in keys:
            # Collector uses last_used_days_ago
            days = key.get(
                "last_used_days_ago"
            )
            status = key.get(
                "status",
                key.get("Status", ""),
            )
            if status == "Active" and (
                days is None or days > 90
            ):
                scores.append(
                    _EXPLOIT_IAM["unused_key"]
                )

        # User without MFA (bool or list)
        mfa = data.get(
            "mfa_enabled",
            data.get("MFADevices"),
        )
        has_name = data.get(
            "name", data.get("UserName")
        )
        if has_name:
            if isinstance(mfa, bool):
                if not mfa:
                    scores.append(
                        _EXPLOIT_IAM["no_mfa"]
                    )
            elif isinstance(mfa, list):
                if not mfa:
                    scores.append(
                        _EXPLOIT_IAM["no_mfa"]
                    )

        return max(scores) if scores else (
            DEFAULT_EXPLOITABILITY
        )

    def _exploit_rds(self, data: dict) -> int:
        """RDS exploitability scoring."""
        scores = []

        if data.get(
            "publicly_accessible",
            data.get("PubliclyAccessible"),
        ):
            scores.append(
                _EXPLOIT_RDS[
                    "publicly_accessible"
                ]
            )

        encrypted = data.get(
            "storage_encrypted",
            data.get("StorageEncrypted", True),
        )
        if not encrypted:
            scores.append(
                _EXPLOIT_RDS["no_encryption"]
            )

        return max(scores) if scores else (
            DEFAULT_EXPLOITABILITY
        )

    def _exploit_lambda(self, data: dict) -> int:
        """Lambda exploitability scoring."""
        policy = data.get(
            "policy",
            data.get("Policy", {}),
        )
        statements = policy.get(
            "Statement", []
        )
        for stmt in statements:
            principal = stmt.get(
                "Principal", ""
            )
            if principal == "*" or (
                isinstance(principal, dict)
                and principal.get("AWS") == "*"
            ):
                return _EXPLOIT_LAMBDA[
                    "public_policy"
                ]
        return DEFAULT_EXPLOITABILITY

    # -- Service-specific blast radius helpers --

    def _blast_iam(self, data: dict) -> int:
        """IAM blast radius scoring."""
        policies = data.get(
            "attached_policies",
            data.get("AttachedPolicies", []),
        )
        for pol in policies:
            name = pol.get(
                "policy_name",
                pol.get("PolicyName", ""),
            ).lower()
            if "admin" in name:
                return _BLAST_IAM["admin_policy"]

        count = data.get(
            "attachment_count",
            data.get("AttachmentCount", 0),
        )
        if count > 10:
            return _BLAST_IAM["many_entities"]
        if count >= 5:
            return _BLAST_IAM["some_entities"]

        return DEFAULT_BLAST_RADIUS

    def _blast_ec2(self, data: dict) -> int:
        """EC2 blast radius scoring."""
        instance_count = data.get(
            "InstanceCount",
            data.get("instance_count", 0),
        )
        if instance_count > 5:
            return _BLAST_EC2["many_instances"]
        if instance_count >= 1:
            return _BLAST_EC2["some_instances"]
        return DEFAULT_BLAST_RADIUS

    def _blast_rds(self, data: dict) -> int:
        """RDS blast radius scoring."""
        multi = data.get(
            "multi_az",
            data.get("MultiAZ"),
        )
        if multi:
            return _BLAST_OTHER["rds_multi_az"]
        return _BLAST_OTHER["rds_single"]


def _extract_tags(data: dict) -> dict:
    """Recursively find Tags in resource data.

    Supports AWS-style Tag arrays [{Key, Value}]
    and flat tag dicts.

    Args:
        data: Resource data dict to search.

    Returns:
        Dict of {key: value} from found tags.
    """
    result = {}
    _search_tags(data, result)
    return result


def _search_tags(
    obj, result: dict, depth: int = 0
) -> None:
    """Recursively search for tag structures.

    Args:
        obj: Current object to inspect.
        result: Dict to populate with tag pairs.
        depth: Current recursion depth (max 10).
    """
    if depth > 10:
        return

    if isinstance(obj, dict):
        for key in ("Tags", "tags"):
            tags = obj.get(key)
            if isinstance(tags, list):
                for tag in tags:
                    if isinstance(tag, dict):
                        k = tag.get(
                            "Key", tag.get("key")
                        )
                        v = tag.get(
                            "Value",
                            tag.get("value", ""),
                        )
                        if k:
                            result[k] = v
            elif isinstance(tags, dict):
                result.update(tags)

        for v in obj.values():
            if isinstance(v, (dict, list)):
                _search_tags(
                    v, result, depth + 1
                )

    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _search_tags(
                    item, result, depth + 1
                )
