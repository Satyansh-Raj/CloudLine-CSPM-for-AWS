"""Container services collector (ECR, ECS, EKS).

The collect_full() method returns separate top-level
keys so that OPA/Rego policies can reference
input.ecs, input.eks, and input.ecr directly.
"""

import json
import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

# EKS versions that have reached end-of-life
_EKS_EOL_VERSIONS = [
    "1.23",
    "1.24",
    "1.25",
    "1.26",
]


class ContainerCollector(BaseCollector):
    """Collects ECR repositories, ECS clusters,
    ECS task definitions, and EKS clusters."""

    # ------------------------------------------------
    # Legacy interface (backward-compatible)
    # ------------------------------------------------

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
                clusters=[resource_id],
                include=["SETTINGS"],
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
                "Container collect_resource: %s",
                e,
            )
        return {}

    # ------------------------------------------------
    # New interface -- separate top-level keys
    # ------------------------------------------------

    def collect_full(self) -> dict:
        """Returns ecs, eks, and ecr as separate
        top-level keys for OPA/Rego policy
        consumption."""
        ecr = self.session.client("ecr")
        ecs = self.session.client("ecs")
        eks = self.session.client("eks")

        eks_clusters = self._get_eks_clusters(eks)
        node_groups = self._get_all_node_groups(
            eks, eks_clusters
        )

        return {
            "ecs": {
                "clusters": (
                    self._get_ecs_clusters(ecs)
                ),
                "task_definitions": (
                    self._get_ecs_task_defs(ecs)
                ),
            },
            "eks": {
                "clusters": eks_clusters,
                "node_groups": node_groups,
                "eol_versions": list(
                    _EKS_EOL_VERSIONS
                ),
            },
            "ecr": {
                "repositories": (
                    self._get_ecr_repos(ecr)
                ),
            },
        }

    # ── ECR ──────────────────────────────────────

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
                "ECR describe_repositories: %s",
                e,
            )
        return repos

    def _build_ecr_repo(
        self, ecr, repo: dict
    ) -> dict:
        arn = repo.get("repositoryArn", "")
        name = repo.get("repositoryName", "")
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

        lifecycle = self._get_ecr_lifecycle(
            ecr, name
        )

        return {
            "repository_name": name,
            "arn": arn,
            "repository_arn": arn,
            "repository_uri": repo.get(
                "repositoryUri", ""
            ),
            "image_tag_mutability": repo.get(
                "imageTagMutability", "MUTABLE"
            ),
            "scan_on_push": scan_cfg.get(
                "scanOnPush", False
            ),
            "image_scanning_configuration": {
                "scan_on_push": scan_cfg.get(
                    "scanOnPush", False
                ),
            },
            "encryption_type": enc_cfg.get(
                "encryptionType", "AES256"
            ),
            "encryption_configuration": {
                "encryption_type": enc_cfg.get(
                    "encryptionType", "AES256"
                ),
                "kms_key": enc_cfg.get(
                    "kmsKey", ""
                ),
            },
            "repository_visibility": "private",
            "lifecycle_policy": lifecycle,
            "tags": tags,
        }

    def _get_ecr_lifecycle(
        self, ecr, repo_name: str
    ) -> dict | None:
        """Fetch the lifecycle policy for an ECR
        repository. Returns parsed JSON or None."""
        try:
            resp = ecr.get_lifecycle_policy(
                repositoryName=repo_name,
            )
            raw = resp.get(
                "lifecyclePolicyText", ""
            )
            if raw:
                return json.loads(raw)
            return None
        except Exception:
            return None

    # ── ECS ──────────────────────────────────────

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
                    clusters=arns,
                    include=["SETTINGS"],
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
        cluster_arn = cluster.get(
            "clusterArn", ""
        )
        settings = self._extract_ecs_settings(
            cluster
        )
        return {
            "cluster_name": cluster.get(
                "clusterName", ""
            ),
            "arn": cluster_arn,
            "cluster_arn": cluster_arn,
            "status": cluster.get(
                "status", "ACTIVE"
            ),
            "running_tasks_count": cluster.get(
                "runningTasksCount", 0
            ),
            "active_services_count": cluster.get(
                "activeServicesCount", 0
            ),
            "settings": settings,
            "tags": tags,
        }

    def _extract_ecs_settings(
        self, cluster: dict
    ) -> list[dict]:
        """Extract cluster settings as a list of
        {name, value} dicts."""
        raw = cluster.get("settings", [])
        return [
            {
                "name": s.get("name", ""),
                "value": s.get("value", ""),
            }
            for s in raw
        ]

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
                container_defs = (
                    self._extract_container_defs(
                        td
                    )
                )
                td_arn = td.get(
                    "taskDefinitionArn", ""
                )
                task_defs.append(
                    {
                        "family": td.get(
                            "family", ""
                        ),
                        "arn": td_arn,
                        "task_definition_arn": (
                            td_arn
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
                        "container_definitions": (
                            container_defs
                        ),
                        "tags": tags,
                    }
                )
        except Exception as e:
            logger.error(
                "ECS list_task_definitions: %s",
                e,
            )
        return task_defs

    def _extract_container_defs(
        self, td: dict
    ) -> list[dict]:
        """Extract container definitions from a
        task definition with fields required by
        Rego policies."""
        raw = td.get(
            "containerDefinitions", []
        )
        result = []
        for cd in raw:
            log_cfg_raw = cd.get(
                "logConfiguration", {}
            )
            log_cfg = {
                "log_driver": log_cfg_raw.get(
                    "logDriver", ""
                ),
            } if log_cfg_raw else {
                "log_driver": "",
            }
            result.append(
                {
                    "name": cd.get("name", ""),
                    "privileged": cd.get(
                        "privileged", False
                    ),
                    "readonly_root_filesystem": (
                        cd.get(
                            "readonlyRootFilesystem",
                            False,
                        )
                    ),
                    "log_configuration": log_cfg,
                }
            )
        return result

    # ── EKS ──────────────────────────────────────

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
        enc_config = self._extract_eks_encryption(
            cluster
        )
        log_config = self._extract_eks_logging(
            cluster
        )
        return {
            "name": cluster.get("name", ""),
            "cluster_name": cluster.get(
                "name", ""
            ),
            "arn": cluster.get("arn", ""),
            "status": cluster.get(
                "status", "ACTIVE"
            ),
            "version": cluster.get(
                "version", ""
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
            "resources_vpc_config": {
                "endpoint_public_access": (
                    vpc_cfg.get(
                        "endpointPublicAccess",
                        True,
                    )
                ),
                "endpoint_private_access": (
                    vpc_cfg.get(
                        "endpointPrivateAccess",
                        False,
                    )
                ),
                "public_access_cidrs": (
                    vpc_cfg.get(
                        "publicAccessCidrs", []
                    )
                ),
                "subnet_ids": vpc_cfg.get(
                    "subnetIds", []
                ),
                "security_group_ids": vpc_cfg.get(
                    "securityGroupIds", []
                ),
            },
            "encryption_config": enc_config,
            "logging": log_config,
            "tags": tags,
        }

    def _extract_eks_encryption(
        self, cluster: dict
    ) -> list[dict]:
        """Extract encryption config from an EKS
        cluster, normalized for Rego consumption."""
        raw = cluster.get(
            "encryptionConfig", []
        )
        result = []
        for item in raw:
            provider_raw = item.get(
                "provider", {}
            )
            result.append(
                {
                    "resources": item.get(
                        "resources", []
                    ),
                    "provider": {
                        "key_arn": provider_raw.get(
                            "keyArn", ""
                        ),
                    },
                }
            )
        return result

    def _extract_eks_logging(
        self, cluster: dict
    ) -> dict:
        """Extract logging config from an EKS
        cluster, normalized for Rego consumption."""
        raw = cluster.get("logging", {})
        cluster_logging_raw = raw.get(
            "clusterLogging", []
        )
        cluster_logging = []
        for entry in cluster_logging_raw:
            cluster_logging.append(
                {
                    "types": entry.get(
                        "types", []
                    ),
                    "enabled": entry.get(
                        "enabled", False
                    ),
                }
            )
        return {
            "cluster_logging": cluster_logging,
        }

    # ── EKS Node Groups ─────────────────────────

    def _get_all_node_groups(
        self,
        eks,
        clusters: list[dict],
    ) -> list[dict]:
        """Collect node groups for all EKS
        clusters."""
        all_groups = []
        for cluster in clusters:
            name = cluster.get("name", "")
            if name:
                groups = (
                    self._get_eks_node_groups(
                        eks, name
                    )
                )
                all_groups.extend(groups)
        return all_groups

    def _get_eks_node_groups(
        self, eks, cluster_name: str
    ) -> list[dict]:
        """List and describe node groups for a
        given EKS cluster."""
        node_groups = []
        try:
            resp = eks.list_nodegroups(
                clusterName=cluster_name,
            )
            for ng_name in resp.get(
                "nodegroups", []
            ):
                try:
                    desc = eks.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng_name,
                    )
                    ng = desc.get(
                        "nodegroup", {}
                    )
                    subnet_ids = ng.get(
                        "subnets", []
                    )
                    subnets = (
                        self._enrich_subnets(
                            subnet_ids
                        )
                    )
                    node_groups.append(
                        {
                            "node_group_name": (
                                ng.get(
                                    "nodegroupName",
                                    "",
                                )
                            ),
                            "node_group_arn": (
                                ng.get(
                                    "nodegroupArn",
                                    "",
                                )
                            ),
                            "cluster_name": (
                                cluster_name
                            ),
                            "subnets": subnets,
                        }
                    )
                except Exception as e:
                    logger.warning(
                        "EKS describe_nodegroup "
                        "%s/%s: %s",
                        cluster_name,
                        ng_name,
                        e,
                    )
        except Exception as e:
            logger.error(
                "EKS list_nodegroups %s: %s",
                cluster_name,
                e,
            )
        return node_groups

    def _enrich_subnets(
        self, subnet_ids: list[str]
    ) -> list[dict]:
        """Query EC2 to get
        map_public_ip_on_launch for each subnet."""
        if not subnet_ids:
            return []
        subnets = []
        try:
            ec2 = self.session.client("ec2")
            resp = ec2.describe_subnets(
                SubnetIds=subnet_ids,
            )
            for s in resp.get("Subnets", []):
                subnets.append(
                    {
                        "subnet_id": s.get(
                            "SubnetId", ""
                        ),
                        "map_public_ip_on_launch": (
                            s.get(
                                "MapPublicIpOnLaunch",
                                False,
                            )
                        ),
                    }
                )
        except Exception as e:
            logger.warning(
                "EC2 describe_subnets: %s", e
            )
            # Fallback: return subnet ids without
            # enrichment
            for sid in subnet_ids:
                subnets.append(
                    {
                        "subnet_id": sid,
                        "map_public_ip_on_launch": (
                            False
                        ),
                    }
                )
        return subnets
