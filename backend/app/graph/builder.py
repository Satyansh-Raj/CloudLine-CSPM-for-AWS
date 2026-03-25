"""Security graph builder service.

Converts a flat list of ResourceRecord and
ViolationState objects into a SecurityGraph with
nodes, edges, and attack-path annotations.
"""

from app.graph.models import (
    GraphEdge,
    GraphNode,
    SecurityGraph,
)
from app.models.resource import ResourceRecord
from app.pipeline.models import ViolationState

# Severity ordering (higher index = higher severity).
_SEVERITY_ORDER = [
    "none",
    "low",
    "medium",
    "high",
    "critical",
]

# Relationship types that represent connectivity /
# privilege and are therefore candidates for attack-
# path flagging.
_CONNECTIVITY_RELS = frozenset(
    {
        "ALLOWS_TRAFFIC",
        "HAS_ROLE",
        "PROTECTED_BY",
        "IN_VPC",
    }
)


def _severity_rank(s: str) -> int:
    """Return numeric rank of a severity string.

    Args:
        s: Severity string.

    Returns:
        Integer rank (0 = none, 4 = critical).
    """
    try:
        return _SEVERITY_ORDER.index(s.lower())
    except ValueError:
        return 0


class SecurityGraphBuilder:
    """Build a SecurityGraph from inventory data.

    Attributes:
        resources: List of ResourceRecord objects
            from the inventory store.
        violations: List of ViolationState objects
            from the state manager.
    """

    def __init__(
        self,
        resources: list[ResourceRecord],
        violations: list[ViolationState],
    ) -> None:
        """Initialise the builder.

        Args:
            resources: Inventory resource records.
            violations: Violation state records.
        """
        self._resources = resources
        self._violations = violations

    def build(self) -> SecurityGraph:
        """Build and return the full security graph.

        Steps:
        1. Create a GraphNode for each resource.
        2. Index violations by resource ARN and
           compute violation_count / max_severity.
        3. Infer edges from resource metadata/tags.
        4. Create phantom nodes for referenced
           resources not in inventory.
        5. Mark attack paths.
        6. Return SecurityGraph with counts.

        Returns:
            Populated SecurityGraph instance.
        """
        # Index violations by resource ARN.
        viol_by_arn: dict[
            str, list[ViolationState]
        ] = {}
        for v in self._violations:
            viol_by_arn.setdefault(
                v.resource_arn, []
            ).append(v)

        # Build nodes keyed by ID.
        nodes_by_id: dict[str, GraphNode] = {}
        for r in self._resources:
            node_id = r.resource_id
            viols = viol_by_arn.get(node_id, [])
            count = len(viols)
            max_sev = _compute_max_severity(viols)
            label = r.resource_name or node_id
            nodes_by_id[node_id] = GraphNode(
                id=node_id,
                label=label,
                resource_type=r.resource_type,
                service=r.service,
                region=r.region,
                violation_count=count,
                max_severity=max_sev,
                risk_score=r.risk_score,
            )

        # Infer edges from resource tags/metadata.
        edges = self._infer_edges(
            nodes_by_id, self._resources
        )

        # Mark attack paths (mutates edge objects).
        self._mark_attack_paths(nodes_by_id, edges)

        # Count attack paths.
        ap_count = sum(
            1 for e in edges if e.attack_path
        )

        return SecurityGraph(
            nodes=list(nodes_by_id.values()),
            edges=edges,
            attack_paths=ap_count,
            total_nodes=len(nodes_by_id),
            total_edges=len(edges),
        )

    def _infer_edges(
        self,
        nodes_by_id: dict[str, GraphNode],
        resources: list[ResourceRecord],
    ) -> list[GraphEdge]:
        """Infer edges from resource tags and metadata.

        Supported tag keys and the edges they produce:
        - vpc_id        → IN_VPC
        - subnet_id     → IN_SUBNET
        - sg_id         → PROTECTED_BY
        - role_arn      → HAS_ROLE
        - iam_role      → HAS_ROLE
        - kms_key_arn   → ENCRYPTED_BY

        When a referenced target is absent from the
        inventory, a phantom node is inserted.

        Args:
            nodes_by_id: Mutable dict of known nodes.
            resources: All resource records.

        Returns:
            List of inferred GraphEdge objects.
        """
        edges: list[GraphEdge] = []

        # Tag key → (relationship, phantom_type,
        #             phantom_service)
        tag_mapping: dict[
            str, tuple[str, str, str]
        ] = {
            "vpc_id": (
                "IN_VPC",
                "vpc",
                "vpc",
            ),
            "subnet_id": (
                "IN_SUBNET",
                "subnet",
                "vpc",
            ),
            "sg_id": (
                "PROTECTED_BY",
                "security_group",
                "ec2",
            ),
            "role_arn": (
                "HAS_ROLE",
                "iam_role",
                "iam",
            ),
            "iam_role": (
                "HAS_ROLE",
                "iam_role",
                "iam",
            ),
            "kms_key_arn": (
                "ENCRYPTED_BY",
                "kms_key",
                "kms",
            ),
        }

        for r in resources:
            source_id = r.resource_id
            tags = r.tags or {}

            for tag_key, (
                rel,
                phantom_type,
                phantom_svc,
            ) in tag_mapping.items():
                target_id = tags.get(tag_key)
                if not target_id:
                    continue

                # Ensure target node exists.
                if target_id not in nodes_by_id:
                    nodes_by_id[target_id] = (
                        _make_phantom_node(
                            node_id=target_id,
                            resource_type=phantom_type,
                            service=phantom_svc,
                            region=r.region,
                        )
                    )

                edges.append(
                    GraphEdge(
                        source=source_id,
                        target=target_id,
                        relationship=rel,
                    )
                )

        return edges

    def _mark_attack_paths(
        self,
        nodes_by_id: dict[str, GraphNode],
        edges: list[GraphEdge],
    ) -> None:
        """Flag edges that lie on a lateral-movement
        attack path.

        An edge is flagged when BOTH conditions hold:
        a. Either source or target node has
           max_severity in {"critical", "high"}.
        b. The relationship type is connectivity-
           related (IN_VPC, HAS_ROLE, PROTECTED_BY,
           ALLOWS_TRAFFIC).

        Args:
            nodes_by_id: Dict of all graph nodes.
            edges: List of edges to annotate
                   (mutated in place).
        """
        high_risk_severities = {"critical", "high"}
        for edge in edges:
            if (
                edge.relationship
                not in _CONNECTIVITY_RELS
            ):
                continue
            src = nodes_by_id.get(edge.source)
            tgt = nodes_by_id.get(edge.target)
            src_sev = (
                src.max_severity if src else "none"
            )
            tgt_sev = (
                tgt.max_severity if tgt else "none"
            )
            if (
                src_sev in high_risk_severities
                or tgt_sev in high_risk_severities
            ):
                edge.attack_path = True


# ---- module-level helpers -----------------------------------


def _compute_max_severity(
    violations: list[ViolationState],
) -> str:
    """Return the highest severity among violations.

    Args:
        violations: Violation state records.

    Returns:
        Severity string or "none" when empty.
    """
    if not violations:
        return "none"
    return max(
        violations,
        key=lambda v: _severity_rank(v.severity),
    ).severity


def _make_phantom_node(
    node_id: str,
    resource_type: str,
    service: str,
    region: str,
) -> GraphNode:
    """Create a minimal phantom node for a resource
    that is referenced but not in the inventory.

    Args:
        node_id: The referenced resource ID / ARN.
        resource_type: Inferred resource type.
        service: Inferred AWS service.
        region: Region of the referencing resource.

    Returns:
        GraphNode with minimal fields set.
    """
    return GraphNode(
        id=node_id,
        label=node_id,
        resource_type=resource_type,
        service=service,
        region=region,
    )
