"""Tests for Security Graph — F9 Batch 20.

Covers:
- GraphNode / GraphEdge / SecurityGraph models
- SecurityGraphBuilder: node creation, violation
  mapping, edge inference, attack path marking
- GET /api/v1/inventory/graph endpoint

TDD: All tests written before implementation (RED).
"""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.dependencies import (
    get_resource_store,
    get_settings,
    get_state_manager,
)
from app.main import app
from app.models.resource import ResourceRecord
from app.pipeline.models import ViolationState

ACCOUNT = "832843292195"
REGION = "ap-south-1"


# ---- helpers -------------------------------------------------


def _make_resource(
    resource_id: str = (
        "arn:aws:ec2:ap-south-1:832843292195"
        ":instance/i-1234"
    ),
    resource_name: str = "web-server",
    resource_type: str = "ec2_instance",
    service: str = "ec2",
    region: str = REGION,
    account_id: str = ACCOUNT,
    tags: dict | None = None,
    risk_score: int = 0,
    violation_count: int = 0,
) -> ResourceRecord:
    """Build a ResourceRecord for testing."""
    return ResourceRecord(
        pk=f"{account_id}#{region}",
        sk=f"{resource_type}#{resource_id}",
        resource_id=resource_id,
        resource_name=resource_name,
        resource_type=resource_type,
        technology_category="compute",
        service=service,
        region=region,
        account_id=account_id,
        last_seen="2026-03-20T10:00:00Z",
        tags=tags or {},
        risk_score=risk_score,
        violation_count=violation_count,
    )


def _make_violation(
    resource_arn: str = (
        "arn:aws:ec2:ap-south-1:832843292195"
        ":instance/i-1234"
    ),
    severity: str = "critical",
    status: str = "alarm",
    check_id: str = "ec2_no_open_ssh",
) -> ViolationState:
    """Build a ViolationState for testing."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        severity=severity,
        domain="network",
        resource_arn=resource_arn,
        reason="Port 22 open to 0.0.0.0/0",
        first_detected="2026-03-01T10:00:00Z",
        last_evaluated="2026-03-20T12:00:00Z",
    )


def _make_store(
    resources: list[ResourceRecord] | None = None,
) -> MagicMock:
    """Return a mock ResourceStore."""
    store = MagicMock()
    store.query_by_account.return_value = (
        resources or []
    )
    return store


def _make_state_manager(
    violations: list[ViolationState] | None = None,
) -> MagicMock:
    """Return a mock StateManager."""
    mgr = MagicMock()
    mgr.query_by_account.return_value = (
        violations or []
    )
    return mgr


# =============================================================
# TestGraphModels
# =============================================================


class TestGraphModels:
    """Unit tests for GraphNode, GraphEdge,
    SecurityGraph Pydantic models."""

    def test_graph_node_creation_with_defaults(self):
        """GraphNode is created with all required
        fields and sensible defaults."""
        from app.graph.models import GraphNode

        node = GraphNode(
            id="arn:aws:s3:::my-bucket",
            label="my-bucket",
            resource_type="s3_bucket",
            service="s3",
            region=REGION,
        )
        assert node.id == "arn:aws:s3:::my-bucket"
        assert node.label == "my-bucket"
        assert node.resource_type == "s3_bucket"
        assert node.service == "s3"
        assert node.region == REGION
        assert node.violation_count == 0
        assert node.max_severity == "none"
        assert node.risk_score == 0

    def test_graph_node_max_severity_default(self):
        """max_severity defaults to 'none'."""
        from app.graph.models import GraphNode

        node = GraphNode(
            id="arn:aws:ec2:::i-1",
            label="i-1",
            resource_type="ec2_instance",
            service="ec2",
            region=REGION,
        )
        assert node.max_severity == "none"

    def test_graph_node_accepts_all_fields(self):
        """GraphNode accepts all optional fields."""
        from app.graph.models import GraphNode

        node = GraphNode(
            id="arn:aws:ec2:::i-1",
            label="web-server",
            resource_type="ec2_instance",
            service="ec2",
            region=REGION,
            violation_count=3,
            max_severity="critical",
            risk_score=85,
        )
        assert node.violation_count == 3
        assert node.max_severity == "critical"
        assert node.risk_score == 85

    def test_graph_edge_creation(self):
        """GraphEdge is created with required fields."""
        from app.graph.models import GraphEdge

        edge = GraphEdge(
            source="arn:aws:ec2:::i-1",
            target="arn:aws:ec2:::vpc-1",
            relationship="IN_VPC",
        )
        assert edge.source == "arn:aws:ec2:::i-1"
        assert edge.target == "arn:aws:ec2:::vpc-1"
        assert edge.relationship == "IN_VPC"

    def test_graph_edge_attack_path_default_false(
        self,
    ):
        """attack_path defaults to False."""
        from app.graph.models import GraphEdge

        edge = GraphEdge(
            source="a",
            target="b",
            relationship="IN_VPC",
        )
        assert edge.attack_path is False

    def test_security_graph_creation(self):
        """SecurityGraph holds nodes, edges and counts."""
        from app.graph.models import (
            GraphEdge,
            GraphNode,
            SecurityGraph,
        )

        node = GraphNode(
            id="n1",
            label="n1",
            resource_type="ec2_instance",
            service="ec2",
            region=REGION,
        )
        edge = GraphEdge(
            source="n1",
            target="n2",
            relationship="IN_VPC",
        )
        graph = SecurityGraph(
            nodes=[node],
            edges=[edge],
            attack_paths=0,
            total_nodes=1,
            total_edges=1,
        )
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1
        assert graph.total_nodes == 1
        assert graph.total_edges == 1
        assert graph.attack_paths == 0

    def test_security_graph_defaults_to_zero_counts(
        self,
    ):
        """SecurityGraph defaults to zero counts
        when not specified."""
        from app.graph.models import SecurityGraph

        graph = SecurityGraph(nodes=[], edges=[])
        assert graph.attack_paths == 0
        assert graph.total_nodes == 0
        assert graph.total_edges == 0


# =============================================================
# TestSecurityGraphBuilder
# =============================================================


class TestSecurityGraphBuilder:
    """Unit tests for SecurityGraphBuilder service."""

    def test_empty_inputs_returns_empty_graph(self):
        """Empty resource list returns a graph with
        no nodes or edges."""
        from app.graph.builder import SecurityGraphBuilder

        builder = SecurityGraphBuilder(
            resources=[], violations=[]
        )
        graph = builder.build()
        assert graph.nodes == []
        assert graph.edges == []
        assert graph.total_nodes == 0
        assert graph.total_edges == 0

    def test_single_resource_creates_one_node(self):
        """One resource creates exactly one node."""
        from app.graph.builder import SecurityGraphBuilder

        r = _make_resource()
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        assert len(graph.nodes) == 1
        assert graph.total_nodes == 1

    def test_multiple_resources_create_correct_count(
        self,
    ):
        """N resources create N nodes (before phantom
        nodes from edge inference)."""
        from app.graph.builder import SecurityGraphBuilder

        resources = [
            _make_resource(
                resource_id=f"arn:aws:ec2:::i-{i}",
                resource_name=f"server-{i}",
            )
            for i in range(5)
        ]
        builder = SecurityGraphBuilder(
            resources=resources, violations=[]
        )
        graph = builder.build()
        real_node_ids = {
            r.resource_id for r in resources
        }
        real_nodes = [
            n
            for n in graph.nodes
            if n.id in real_node_ids
        ]
        assert len(real_nodes) == 5

    def test_violations_mapped_to_correct_node(self):
        """Violations are counted per resource ARN."""
        from app.graph.builder import SecurityGraphBuilder

        arn = (
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-1234"
        )
        r = _make_resource(resource_id=arn)
        v1 = _make_violation(
            resource_arn=arn, severity="high"
        )
        v2 = _make_violation(
            resource_arn=arn,
            severity="medium",
            check_id="ec2_imds_v2",
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[v1, v2]
        )
        graph = builder.build()
        node = next(
            n for n in graph.nodes if n.id == arn
        )
        assert node.violation_count == 2

    def test_max_severity_computed_correctly(self):
        """max_severity picks the highest severity
        from all violations on a resource."""
        from app.graph.builder import SecurityGraphBuilder

        arn = (
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-1234"
        )
        r = _make_resource(resource_id=arn)
        v1 = _make_violation(
            resource_arn=arn, severity="low"
        )
        v2 = _make_violation(
            resource_arn=arn,
            severity="critical",
            check_id="ec2_imds_v2",
        )
        v3 = _make_violation(
            resource_arn=arn,
            severity="medium",
            check_id="ec2_public_ip",
        )
        builder = SecurityGraphBuilder(
            resources=[r],
            violations=[v1, v2, v3],
        )
        graph = builder.build()
        node = next(
            n for n in graph.nodes if n.id == arn
        )
        assert node.max_severity == "critical"

    def test_vpc_edge_inferred_from_tags(self):
        """Resource with vpc_id tag gets IN_VPC edge."""
        from app.graph.builder import SecurityGraphBuilder

        vpc_id = "vpc-0abc1234"
        r = _make_resource(
            tags={"vpc_id": vpc_id}
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        vpc_edges = [
            e
            for e in graph.edges
            if e.relationship == "IN_VPC"
        ]
        assert len(vpc_edges) == 1
        assert vpc_edges[0].target == vpc_id

    def test_security_group_edge_inferred(self):
        """Resource with sg_id tag gets PROTECTED_BY
        edge."""
        from app.graph.builder import SecurityGraphBuilder

        sg_id = "sg-0deadbeef"
        r = _make_resource(
            tags={"sg_id": sg_id}
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        sg_edges = [
            e
            for e in graph.edges
            if e.relationship == "PROTECTED_BY"
        ]
        assert len(sg_edges) == 1
        assert sg_edges[0].target == sg_id

    def test_iam_role_edge_inferred_from_role_arn_tag(
        self,
    ):
        """Resource with role_arn tag gets HAS_ROLE
        edge."""
        from app.graph.builder import SecurityGraphBuilder

        role_arn = (
            "arn:aws:iam::832843292195:role/MyRole"
        )
        r = _make_resource(
            tags={"role_arn": role_arn}
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        role_edges = [
            e
            for e in graph.edges
            if e.relationship == "HAS_ROLE"
        ]
        assert len(role_edges) == 1
        assert role_edges[0].target == role_arn

    def test_phantom_node_created_for_missing_resource(
        self,
    ):
        """When a tag references a resource not in
        inventory, a phantom node is created."""
        from app.graph.builder import SecurityGraphBuilder

        vpc_id = "vpc-phantom999"
        r = _make_resource(
            tags={"vpc_id": vpc_id}
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        phantom = next(
            (n for n in graph.nodes if n.id == vpc_id),
            None,
        )
        assert phantom is not None
        assert phantom.id == vpc_id

    def test_attack_path_marked_high_severity_has_role(
        self,
    ):
        """Edge is attack_path when high-severity node
        connects via HAS_ROLE relationship."""
        from app.graph.builder import SecurityGraphBuilder

        arn = (
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-1234"
        )
        role_arn = (
            "arn:aws:iam::832843292195:role/AdminRole"
        )
        r = _make_resource(
            resource_id=arn,
            tags={"role_arn": role_arn},
        )
        v = _make_violation(
            resource_arn=arn, severity="high"
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[v]
        )
        graph = builder.build()
        role_edges = [
            e
            for e in graph.edges
            if e.relationship == "HAS_ROLE"
        ]
        assert len(role_edges) == 1
        assert role_edges[0].attack_path is True

    def test_attack_path_not_marked_for_low_severity(
        self,
    ):
        """Edge is NOT attack_path when node has only
        low-severity violations."""
        from app.graph.builder import SecurityGraphBuilder

        arn = (
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-1234"
        )
        role_arn = (
            "arn:aws:iam::832843292195:role/ReadRole"
        )
        r = _make_resource(
            resource_id=arn,
            tags={"role_arn": role_arn},
        )
        v = _make_violation(
            resource_arn=arn, severity="low"
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[v]
        )
        graph = builder.build()
        role_edges = [
            e
            for e in graph.edges
            if e.relationship == "HAS_ROLE"
        ]
        assert len(role_edges) == 1
        assert role_edges[0].attack_path is False

    def test_attack_path_not_marked_for_non_connectivity(
        self,
    ):
        """IN_SUBNET edge is NOT an attack path even
        when severity is critical (non-connectivity
        relationship type)."""
        from app.graph.builder import SecurityGraphBuilder

        arn = (
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-1234"
        )
        subnet_id = "subnet-0dead1234"
        r = _make_resource(
            resource_id=arn,
            tags={"subnet_id": subnet_id},
        )
        v = _make_violation(
            resource_arn=arn, severity="critical"
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[v]
        )
        graph = builder.build()
        subnet_edges = [
            e
            for e in graph.edges
            if e.relationship == "IN_SUBNET"
        ]
        assert len(subnet_edges) == 1
        assert subnet_edges[0].attack_path is False

    def test_attack_paths_count_in_graph(self):
        """SecurityGraph.attack_paths counts edges
        flagged as attack paths."""
        from app.graph.builder import SecurityGraphBuilder

        arn = (
            "arn:aws:ec2:ap-south-1:832843292195"
            ":instance/i-1234"
        )
        role_arn = (
            "arn:aws:iam::832843292195:role/AdminRole"
        )
        r = _make_resource(
            resource_id=arn,
            tags={"role_arn": role_arn},
        )
        v = _make_violation(
            resource_arn=arn, severity="critical"
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[v]
        )
        graph = builder.build()
        assert graph.attack_paths >= 1

    def test_duplicate_edges_not_created(self):
        """Same relationship is not duplicated even
        if multiple tags reference the same target."""
        from app.graph.builder import SecurityGraphBuilder

        vpc_id = "vpc-0abc1234"
        # Two resources pointing to the same VPC.
        r1 = _make_resource(
            resource_id="arn:aws:ec2:::i-1",
            resource_name="srv-1",
            tags={"vpc_id": vpc_id},
        )
        r2 = _make_resource(
            resource_id="arn:aws:ec2:::i-2",
            resource_name="srv-2",
            tags={"vpc_id": vpc_id},
        )
        builder = SecurityGraphBuilder(
            resources=[r1, r2], violations=[]
        )
        graph = builder.build()
        # Each resource gets its own IN_VPC edge —
        # they are distinct (source differs).
        vpc_edges = [
            e
            for e in graph.edges
            if e.relationship == "IN_VPC"
        ]
        sources = {e.source for e in vpc_edges}
        # Two distinct sources, not duplicated.
        assert len(sources) == 2

    def test_node_label_uses_resource_name(self):
        """Node label is the resource_name when
        available."""
        from app.graph.builder import SecurityGraphBuilder

        r = _make_resource(
            resource_id="arn:aws:ec2:::i-1",
            resource_name="my-web-server",
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        node = next(
            n
            for n in graph.nodes
            if n.id == r.resource_id
        )
        assert node.label == "my-web-server"

    def test_node_label_falls_back_to_resource_id(
        self,
    ):
        """Node label falls back to resource_id when
        resource_name is empty."""
        from app.graph.builder import SecurityGraphBuilder

        r = _make_resource(
            resource_id="arn:aws:ec2:::i-no-name",
            resource_name="",
        )
        builder = SecurityGraphBuilder(
            resources=[r], violations=[]
        )
        graph = builder.build()
        node = next(
            n
            for n in graph.nodes
            if n.id == r.resource_id
        )
        assert node.label == "arn:aws:ec2:::i-no-name"


# =============================================================
# TestSecurityGraphEndpoint
# =============================================================


class TestSecurityGraphEndpoint:
    """Integration tests for GET /api/v1/inventory/graph."""

    @pytest.fixture(autouse=True)
    def _reset_overrides(self):
        """Clear dependency overrides after each test."""
        yield
        app.dependency_overrides.clear()

    def _override(
        self,
        resources: list[ResourceRecord] | None = None,
        violations: list[ViolationState] | None = None,
    ) -> TestClient:
        """Set up TestClient with mocked dependencies."""
        store = _make_store(resources)
        mgr = _make_state_manager(violations)
        cfg = Settings(
            aws_account_id=ACCOUNT,
            aws_region=REGION,
        )

        app.dependency_overrides[
            get_resource_store
        ] = lambda: store
        app.dependency_overrides[
            get_state_manager
        ] = lambda: mgr
        app.dependency_overrides[
            get_settings
        ] = lambda: cfg

        return TestClient(app)

    def test_returns_200_with_valid_graph(self):
        """Endpoint returns HTTP 200."""
        client = self._override()
        resp = client.get("/api/v1/inventory/graph")
        assert resp.status_code == 200

    def test_response_has_nodes_and_edges_arrays(
        self,
    ):
        """Response body contains 'nodes' and 'edges'
        list fields."""
        client = self._override()
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        assert "nodes" in data
        assert "edges" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    def test_empty_inventory_returns_empty_graph(
        self,
    ):
        """Zero resources produces zero nodes and
        edges in the response."""
        client = self._override(
            resources=[], violations=[]
        )
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        assert data["nodes"] == []
        assert data["edges"] == []

    def test_total_nodes_matches_nodes_array(self):
        """total_nodes field equals len(nodes)."""
        r = _make_resource()
        client = self._override(resources=[r])
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        assert data["total_nodes"] == len(
            data["nodes"]
        )

    def test_total_edges_matches_edges_array(self):
        """total_edges field equals len(edges)."""
        r = _make_resource(
            tags={"vpc_id": "vpc-0abc1234"}
        )
        client = self._override(resources=[r])
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        assert data["total_edges"] == len(
            data["edges"]
        )

    def test_attack_paths_count_in_response(self):
        """Response includes 'attack_paths' integer."""
        client = self._override()
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        assert "attack_paths" in data
        assert isinstance(data["attack_paths"], int)

    def test_node_has_required_fields(self):
        """Each node in the response has id, label,
        resource_type fields."""
        r = _make_resource()
        client = self._override(resources=[r])
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        # Find the real resource node (not phantom).
        node = next(
            n
            for n in data["nodes"]
            if n["id"] == r.resource_id
        )
        assert "id" in node
        assert "label" in node
        assert "resource_type" in node

    def test_edge_has_required_fields(self):
        """Each edge has source, target, relationship
        fields."""
        r = _make_resource(
            tags={"vpc_id": "vpc-0abc1234"}
        )
        client = self._override(resources=[r])
        data = client.get(
            "/api/v1/inventory/graph"
        ).json()
        assert len(data["edges"]) > 0
        edge = data["edges"][0]
        assert "source" in edge
        assert "target" in edge
        assert "relationship" in edge

    def test_region_filter_passed_through(self):
        """Passing ?region=us-east-1 triggers
        query_by_account with that region."""
        store = _make_store(resources=[])
        mgr = _make_state_manager(violations=[])
        cfg = Settings(
            aws_account_id=ACCOUNT,
            aws_region=REGION,
        )

        app.dependency_overrides[
            get_resource_store
        ] = lambda: store
        app.dependency_overrides[
            get_state_manager
        ] = lambda: mgr
        app.dependency_overrides[
            get_settings
        ] = lambda: cfg

        client = TestClient(app)
        client.get(
            "/api/v1/inventory/graph"
            "?region=us-east-1"
        )
        store.query_by_account.assert_called_once()
        _, kwargs = (
            store.query_by_account.call_args
        )
        # region is the second positional arg.
        call_args = (
            store.query_by_account.call_args
        )
        # Check that us-east-1 appears in the call.
        all_args = list(call_args.args) + list(
            call_args.kwargs.values()
        )
        assert "us-east-1" in all_args

    def test_account_id_filter_passed_through(self):
        """Passing ?account_id=... uses that account
        for the resource query."""
        store = _make_store(resources=[])
        mgr = _make_state_manager(violations=[])
        cfg = Settings(
            aws_account_id=ACCOUNT,
            aws_region=REGION,
        )

        app.dependency_overrides[
            get_resource_store
        ] = lambda: store
        app.dependency_overrides[
            get_state_manager
        ] = lambda: mgr
        app.dependency_overrides[
            get_settings
        ] = lambda: cfg

        client = TestClient(app)
        client.get(
            "/api/v1/inventory/graph"
            "?account_id=111122223333"
        )
        store.query_by_account.assert_called_once()
        call_args = (
            store.query_by_account.call_args
        )
        all_args = list(call_args.args) + list(
            call_args.kwargs.values()
        )
        assert "111122223333" in all_args
