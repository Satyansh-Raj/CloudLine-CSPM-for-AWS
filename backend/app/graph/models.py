"""Pydantic models for the security graph.

Defines GraphNode, GraphEdge, and SecurityGraph
response model used by the inventory graph endpoint.
"""

from pydantic import BaseModel


class GraphNode(BaseModel):
    """A node in the security resource graph.

    Attributes:
        id: Unique node identifier (ARN or resource
            ID).
        label: Display name for the node.
        resource_type: Normalized AWS resource type
            (e.g. "ec2_instance", "s3_bucket").
        service: AWS service name (e.g. "ec2", "s3").
        region: AWS region of the resource.
        violation_count: Number of active violations
            on this resource.
        max_severity: Highest severity among violations
            (none/low/medium/high/critical).
        risk_score: Composite risk score (0-100) from
            resource inventory.
    """

    id: str
    label: str
    resource_type: str
    service: str
    region: str
    violation_count: int = 0
    max_severity: str = "none"
    risk_score: int = 0


class GraphEdge(BaseModel):
    """A directed edge in the security resource graph.

    Attributes:
        source: Source node ID.
        target: Target node ID.
        relationship: Semantic relationship label
            (e.g. "IN_VPC", "HAS_ROLE",
            "PROTECTED_BY", "IN_SUBNET",
            "ENCRYPTED_BY", "CONTAINS").
        attack_path: True if this edge is on a
            critical lateral-movement path.
    """

    source: str
    target: str
    relationship: str
    attack_path: bool = False


class SecurityGraph(BaseModel):
    """Complete security resource graph response.

    Attributes:
        nodes: All resource nodes.
        edges: All directed edges.
        attack_paths: Count of edges flagged as
            attack paths.
        total_nodes: Convenience count of nodes.
        total_edges: Convenience count of edges.
    """

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    attack_paths: int = 0
    total_nodes: int = 0
    total_edges: int = 0
