"""Container services collector (ECR, ECS, EKS)."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ContainerCollector(BaseCollector):
    """Collects ECR repositories, ECS clusters,
    ECS task definitions, and EKS clusters."""

    def collect(self) -> tuple[str, dict]:
        ecr = self.session.client("ecr")
        ecs = self.session.client("ecs")
        eks = self.session.client("eks")
        return "containers", {
            "ecr_repositories": (
                self._get_ecr_repos(ecr)
            ),
            "ecs_clusters": (
                self._get_ecs_clusters(ecs)
            ),
            "ecs_task_definitions": (
                self._get_ecs_task_defs(ecs)
            ),
            "eks_clusters": (
                self._get_eks_clusters(eks)
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        if "/" in resource_id:
            ecr = self.session.client("ecr")
            try:
                resp = ecr.describe_repositories(
                    repositoryNames=[resource_id]
                )
                repos = resp.get(
                    "repositories", []
                )
                if repos:
                    return self._build_ecr_repo(
                        ecr, repos[0]
                    )
            except Exception:
                pass
        ecs = self.session.client("ecs")
        try:
            resp = ecs.describe_clusters(
                clusters=[resource_id]
            )
            clusters = resp.get("clusters", [])
            if clusters:
                return self._build_ecs_cluster(
                    clusters[0]
                )
        except Exception:
            pass
        eks = self.session.client("eks")
        try:
            resp = eks.describe_cluster(
                name=resource_id
            )
            cluster = resp.get("cluster", {})
            if cluster:
                return self._build_eks_cluster(
                    cluster
                )
        except Exception as e:
            logger.error(
                "Container collect_resource: %s", e
            )
        return {}

    # ── ECR ────────────────────────────────────

    def _get_ecr_repos(
        self, ecr
    ) -> list[dict]:
        repos = []
        try:
            paginator = ecr.get_paginator(
                "describe_repositories"
            )
            for page in paginator.paginate():
                for repo in page.get(
                    "repositories", []
                ):
                    repos.append(
                        self._build_ecr_repo(
                            ecr, repo
                        )
                    )
        except Exception as e:
            logger.error(
                "ECR describe_repositories: %s", e
            )
        return repos

    def _build_ecr_repo(
        self, ecr, repo: dict
    ) -> dict:
        arn = repo.get("repositoryArn", "")
        scan_cfg = repo.get(
            "imageScanningConfiguration", {}
        )
        enc_cfg = repo.get(
            "encryptionConfiguration", {}
        )
        tags = {}
        try:
            tag_resp = ecr.list_tags_for_resource(
                resourceArn=arn
            )
            tags = {
                t["Key"]: t["Value"]
                for t in tag_resp.get("tags", [])
            }
        except Exception:
            pass
        return {
            "repository_name": repo.get(
                "repositoryName", ""
            ),
            "arn": arn,
            "repository_uri": repo.get(
                "repositoryUri", ""
            ),
            "image_tag_mutability": repo.get(
                "imageTagMutability", "MUTABLE"
            ),
            "scan_on_push": scan_cfg.get(
                "scanOnPush", False
            ),
            "encryption_type": enc_cfg.get(
                "encryptionType", "AES256"
            ),
            "tags": tags,
        }

    # ── ECS ────────────────────────────────────

    def _get_ecs_clusters(
        self, ecs
    ) -> list[dict]:
        clusters = []
        try:
            resp = ecs.list_clusters()
            arns = resp.get(
                "clusterArns", []
            )
            if arns:
                desc = ecs.describe_clusters(
                    clusters=arns
                )
                for c in desc.get(
                    "clusters", []
                ):
                    clusters.append(
                        self._build_ecs_cluster(c)
                    )
        except Exception as e:
            logger.error(
                "ECS list_clusters: %s", e
            )
        return clusters

    def _build_ecs_cluster(
        self, cluster: dict
    ) -> dict:
        tags = {
            t["key"]: t["value"]
            for t in cluster.get("tags", [])
        }
        return {
            "cluster_name": cluster.get(
                "clusterName", ""
            ),
            "arn": cluster.get(
                "clusterArn", ""
            ),
            "status": cluster.get(
                "status", "ACTIVE"
            ),
            "running_tasks_count": cluster.get(
                "runningTasksCount", 0
            ),
            "active_services_count": cluster.get(
                "activeServicesCount", 0
            ),
            "tags": tags,
        }

    def _get_ecs_task_defs(
        self, ecs
    ) -> list[dict]:
        task_defs = []
        try:
            resp = ecs.list_task_definitions(
                status="ACTIVE"
            )
            for arn in resp.get(
                "taskDefinitionArns", []
            ):
                desc = ecs.describe_task_definition(
                    taskDefinition=arn
                )
                td = desc.get(
                    "taskDefinition", {}
                )
                tags_resp = desc.get("tags", [])
                tags = {
                    t["key"]: t["value"]
                    for t in tags_resp
                }
                task_defs.append(
                    {
                        "family": td.get(
                            "family", ""
                        ),
                        "arn": td.get(
                            "taskDefinitionArn",
                            "",
                        ),
                        "revision": td.get(
                            "revision", 0
                        ),
                        "status": td.get(
                            "status", "ACTIVE"
                        ),
                        "network_mode": td.get(
                            "networkMode", ""
                        ),
                        "requires_compatibilities": (
                            td.get(
                                "requiresCompatibilities",
                                [],
                            )
                        ),
                        "tags": tags,
                    }
                )
        except Exception as e:
            logger.error(
                "ECS list_task_definitions: %s", e
            )
        return task_defs

    # ── EKS ────────────────────────────────────

    def _get_eks_clusters(
        self, eks
    ) -> list[dict]:
        clusters = []
        try:
            resp = eks.list_clusters()
            for name in resp.get(
                "clusters", []
            ):
                desc = eks.describe_cluster(
                    name=name
                )
                clusters.append(
                    self._build_eks_cluster(
                        desc["cluster"]
                    )
                )
        except Exception as e:
            logger.error(
                "EKS list_clusters: %s", e
            )
        return clusters

    def _build_eks_cluster(
        self, cluster: dict
    ) -> dict:
        vpc_cfg = cluster.get(
            "resourcesVpcConfig", {}
        )
        tags = cluster.get("tags", {})
        return {
            "cluster_name": cluster.get(
                "name", ""
            ),
            "arn": cluster.get("arn", ""),
            "status": cluster.get(
                "status", "ACTIVE"
            ),
            "kubernetes_version": cluster.get(
                "version", ""
            ),
            "endpoint_public_access": vpc_cfg.get(
                "endpointPublicAccess", True
            ),
            "endpoint_private_access": vpc_cfg.get(
                "endpointPrivateAccess", False
            ),
            "tags": tags,
        }
