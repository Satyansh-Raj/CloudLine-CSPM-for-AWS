"""Tests for Container collector using moto."""

import pytest

from app.collectors.container import (
    ContainerCollector,
)


@pytest.fixture
def ecr_setup(mock_session):
    """Set up ECR repository for testing."""
    ecr = mock_session.client("ecr")
    ecr.create_repository(
        repositoryName="my-app",
        imageTagMutability="IMMUTABLE",
        imageScanningConfiguration={
            "scanOnPush": True,
        },
    )
    return mock_session


@pytest.fixture
def ecs_setup(mock_session):
    """Set up ECS cluster and task definition."""
    ecs = mock_session.client("ecs")
    ecs.create_cluster(clusterName="prod-cluster")
    ecs.register_task_definition(
        family="web-app",
        containerDefinitions=[
            {
                "name": "web",
                "image": "nginx:latest",
                "memory": 512,
            },
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
    )
    return mock_session


@pytest.fixture
def eks_setup(mock_session):
    """Set up EKS cluster for testing."""
    eks = mock_session.client("eks")
    eks.create_cluster(
        name="k8s-prod",
        roleArn=(
            "arn:aws:iam::123456789012"
            ":role/eks-role"
        ),
        resourcesVpcConfig={
            "subnetIds": ["subnet-12345"],
            "securityGroupIds": ["sg-12345"],
        },
    )
    return mock_session


class TestContainerCollectorECR:
    """Tests for ECR collection."""

    def test_collect_returns_containers_key(
        self, ecr_setup
    ):
        collector = ContainerCollector(ecr_setup)
        key, _ = collector.collect()
        assert key == "containers"

    def test_collect_has_ecr_repos(
        self, ecr_setup
    ):
        collector = ContainerCollector(ecr_setup)
        _, data = collector.collect()
        assert "ecr_repositories" in data
        assert len(data["ecr_repositories"]) >= 1

    def test_ecr_repo_name(self, ecr_setup):
        collector = ContainerCollector(ecr_setup)
        _, data = collector.collect()
        names = [
            r["repository_name"]
            for r in data["ecr_repositories"]
        ]
        assert "my-app" in names

    def test_ecr_repo_has_arn(self, ecr_setup):
        collector = ContainerCollector(ecr_setup)
        _, data = collector.collect()
        repo = next(
            r
            for r in data["ecr_repositories"]
            if r["repository_name"] == "my-app"
        )
        assert repo["arn"] != ""

    def test_ecr_scan_on_push(self, ecr_setup):
        collector = ContainerCollector(ecr_setup)
        _, data = collector.collect()
        repo = next(
            r
            for r in data["ecr_repositories"]
            if r["repository_name"] == "my-app"
        )
        assert repo["scan_on_push"] is True

    def test_ecr_tag_mutability(
        self, ecr_setup
    ):
        collector = ContainerCollector(ecr_setup)
        _, data = collector.collect()
        repo = next(
            r
            for r in data["ecr_repositories"]
            if r["repository_name"] == "my-app"
        )
        assert (
            repo["image_tag_mutability"]
            == "IMMUTABLE"
        )


class TestContainerCollectorECS:
    """Tests for ECS collection."""

    def test_collect_has_ecs_clusters(
        self, ecs_setup
    ):
        collector = ContainerCollector(ecs_setup)
        _, data = collector.collect()
        assert "ecs_clusters" in data
        assert len(data["ecs_clusters"]) >= 1

    def test_ecs_cluster_name(self, ecs_setup):
        collector = ContainerCollector(ecs_setup)
        _, data = collector.collect()
        names = [
            c["cluster_name"]
            for c in data["ecs_clusters"]
        ]
        assert "prod-cluster" in names

    def test_ecs_cluster_has_arn(
        self, ecs_setup
    ):
        collector = ContainerCollector(ecs_setup)
        _, data = collector.collect()
        cluster = next(
            c
            for c in data["ecs_clusters"]
            if c["cluster_name"] == "prod-cluster"
        )
        assert cluster["arn"] != ""

    def test_collect_has_task_definitions(
        self, ecs_setup
    ):
        collector = ContainerCollector(ecs_setup)
        _, data = collector.collect()
        assert "ecs_task_definitions" in data
        assert (
            len(data["ecs_task_definitions"]) >= 1
        )

    def test_task_def_family(self, ecs_setup):
        collector = ContainerCollector(ecs_setup)
        _, data = collector.collect()
        families = [
            td["family"]
            for td in data["ecs_task_definitions"]
        ]
        assert "web-app" in families

    def test_task_def_network_mode(
        self, ecs_setup
    ):
        collector = ContainerCollector(ecs_setup)
        _, data = collector.collect()
        td = next(
            t
            for t in data["ecs_task_definitions"]
            if t["family"] == "web-app"
        )
        assert td["network_mode"] == "awsvpc"


class TestContainerCollectorEKS:
    """Tests for EKS collection."""

    def test_collect_has_eks_clusters(
        self, eks_setup
    ):
        collector = ContainerCollector(eks_setup)
        _, data = collector.collect()
        assert "eks_clusters" in data
        assert len(data["eks_clusters"]) >= 1

    def test_eks_cluster_name(self, eks_setup):
        collector = ContainerCollector(eks_setup)
        _, data = collector.collect()
        names = [
            c["cluster_name"]
            for c in data["eks_clusters"]
        ]
        assert "k8s-prod" in names

    def test_eks_cluster_has_arn(
        self, eks_setup
    ):
        collector = ContainerCollector(eks_setup)
        _, data = collector.collect()
        cluster = next(
            c
            for c in data["eks_clusters"]
            if c["cluster_name"] == "k8s-prod"
        )
        assert cluster["arn"] != ""

    def test_eks_endpoint_access(
        self, eks_setup
    ):
        collector = ContainerCollector(eks_setup)
        _, data = collector.collect()
        cluster = next(
            c
            for c in data["eks_clusters"]
            if c["cluster_name"] == "k8s-prod"
        )
        assert "endpoint_public_access" in cluster

    def test_collect_resource_eks(
        self, eks_setup
    ):
        collector = ContainerCollector(eks_setup)
        result = collector.collect_resource(
            "k8s-prod"
        )
        assert result["cluster_name"] == (
            "k8s-prod"
        )

    def test_collect_resource_not_found(
        self, mock_session
    ):
        collector = ContainerCollector(
            mock_session
        )
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}


class TestContainerCollectorEmpty:
    """Tests with no resources."""

    def test_empty_ecr(self, mock_session):
        collector = ContainerCollector(
            mock_session
        )
        _, data = collector.collect()
        assert data["ecr_repositories"] == []

    def test_empty_eks(self, mock_session):
        collector = ContainerCollector(
            mock_session
        )
        _, data = collector.collect()
        assert data["eks_clusters"] == []
