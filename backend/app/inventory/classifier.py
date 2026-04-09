"""Resource classifier orchestrator.

Takes UnifiedAWSInput from a scan and produces a list
of ResourceRecord objects ready for DynamoDB persistence.
Uses ExposureClassifier for network-path analysis and
taxonomy mappings for categorisation.
"""

import logging
from datetime import UTC, datetime

from app.inventory.exposure import ExposureClassifier
from app.inventory.taxonomy import get_taxonomy
from app.models.aws_input import UnifiedAWSInput
from app.models.resource import ResourceRecord

# Imported lazily in enrich_with_data_classification
# to avoid a circular-import risk and keep the module
# testable without the full compliance stack.


logger = logging.getLogger(__name__)

# Tag keys checked for environment (case-insensitive).
_ENV_KEYS = ("environment", "env", "stage")

# Normalisation map for common environment values.
_ENV_ALIASES: dict[str, str] = {
    "production": "prod",
    "development": "dev",
}

# Tag keys checked for owner.
_OWNER_KEYS = ("owner", "team", "maintainer")


def extract_env_owner(
    tags: dict,
) -> tuple[str, str]:
    """Extract environment and owner from tags.

    Args:
        tags: AWS resource tags dict.

    Returns:
        (environment, owner) — defaults to
        ('unknown', '') when absent.
    """
    env = "unknown"
    owner = ""

    lower_tags = {
        k.lower(): v for k, v in tags.items()
    }

    for key in _ENV_KEYS:
        if key in lower_tags:
            raw = lower_tags[key].lower()
            env = _ENV_ALIASES.get(raw, raw)
            break

    for key in _OWNER_KEYS:
        if key in lower_tags:
            owner = tags[
                next(
                    k for k in tags
                    if k.lower() == key
                )
            ]
            break

    return env, owner


_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


def _compute_risk_score(alarms: list) -> int:
    """Aggregate risk score from violation severities.

    Each violation contributes points based on severity.
    Result is clamped to 0-100.

    Args:
        alarms: List of alarm-status violations.

    Returns:
        Risk score integer (0-100).
    """
    total = sum(
        _SEVERITY_WEIGHTS.get(
            getattr(v, "severity", "").lower(), 0
        )
        for v in alarms
    )
    return min(total, 100)


class ResourceClassifier:
    """Builds ResourceRecord list from collected data.

    Attributes:
        account_id: AWS account ID.
        region: AWS region.
    """

    def __init__(
        self, account_id: str, region: str
    ):
        self.account_id = account_id
        self.region = region

    def classify_all(
        self, input_data: UnifiedAWSInput
    ) -> list[ResourceRecord]:
        """Classify every resource in the input.

        Returns:
            List of ResourceRecord, one per resource.
        """
        now = (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        exposure = ExposureClassifier(input_data)
        records: list[ResourceRecord] = []

        # EC2 instances
        for inst in input_data.ec2.instances:
            records.append(
                self._ec2(inst, exposure, now)
            )

        # S3 buckets
        for bkt in input_data.s3.buckets:
            records.append(
                self._s3(bkt, exposure, now)
            )

        # RDS instances
        for db in input_data.rds.db_instances:
            records.append(
                self._rds(db, exposure, now)
            )

        # Lambda functions
        for fn in input_data.lambda_functions:
            records.append(
                self._lambda(fn, exposure, now)
            )

        # EBS volumes
        for vol in input_data.ec2.ebs_volumes:
            records.append(self._ebs(vol, now))

        # Security groups
        for sg in input_data.ec2.security_groups:
            records.append(self._sg(sg, now))

        # VPCs
        for vpc in input_data.vpc.vpcs:
            records.append(self._vpc(vpc, now))

        # KMS keys
        for key in input_data.kms.keys:
            records.append(self._kms(key, now))

        # Secrets
        for sec in input_data.secrets_manager.secrets:
            records.append(self._secret(sec, now))

        # IAM users
        for user in input_data.iam.users:
            records.append(
                self._iam_user(user, now)
            )

        # IAM groups
        for grp in input_data.iam.groups:
            records.append(
                self._iam_group(grp, now)
            )

        # IAM roles
        for role in input_data.iam.roles:
            records.append(
                self._iam_role(role, now)
            )

        # IAM policies
        for pol in input_data.iam.customer_managed_policies:
            records.append(
                self._iam_policy(pol, now)
            )

        # CloudTrail trails
        for trail in input_data.cloudtrail.trails:
            records.append(
                self._cloudtrail(trail, now)
            )

        # GuardDuty detectors
        for det in input_data.guardduty.detectors:
            records.append(
                self._guardduty(det, now)
            )

        # CloudWatch alarms
        for alarm in input_data.cloudwatch.alarms:
            records.append(
                self._cloudwatch_alarm(alarm, now)
            )

        # Network ACLs
        for nacl in input_data.vpc.nacls:
            records.append(
                self._network_acl(nacl, now)
            )

        # Subnets
        for sub in input_data.vpc.subnets:
            records.append(
                self._subnet(sub, now)
            )

        # Internet Gateways
        for igw in input_data.vpc.internet_gateways:
            records.append(
                self._internet_gateway(igw, now)
            )

        # NAT Gateways
        for nat in input_data.vpc.nat_gateways:
            records.append(
                self._nat_gateway(nat, now)
            )

        # Network Firewalls
        for nf in input_data.vpc.network_firewalls:
            records.append(
                self._network_firewall(nf, now)
            )

        # WAF Web ACLs
        for waf in input_data.vpc.waf_web_acls:
            records.append(
                self._waf_web_acl(waf, now)
            )

        # Aurora clusters
        for ac in input_data.rds.aurora_clusters:
            records.append(
                self._aurora_cluster(ac, now)
            )

        # RDS snapshots
        for snap in input_data.rds.snapshots:
            records.append(
                self._rds_snapshot(snap, now)
            )

        # DynamoDB tables
        for tbl in input_data.dynamodb.tables:
            records.append(
                self._dynamodb_table(tbl, now)
            )

        # Load Balancers
        for lb in input_data.elb.load_balancers:
            records.append(
                self._load_balancer(lb, now)
            )

        # CloudFront distributions
        for dist in input_data.cdn.distributions:
            records.append(
                self._cloudfront(dist, now)
            )

        # Route53 hosted zones
        for zone in input_data.cdn.hosted_zones:
            records.append(
                self._route53(zone, now)
            )

        # Auto Scaling Groups
        for asg in (
            input_data.ec2.auto_scaling_groups
        ):
            records.append(
                self._auto_scaling_group(asg, now)
            )

        # EBS Snapshots
        for snap in input_data.ec2.ebs_snapshots:
            records.append(
                self._ebs_snapshot(snap, now)
            )

        # API Gateways
        for api in input_data.apigateway.rest_apis:
            records.append(
                self._api_gateway(api, now)
            )

        # ECR Repositories
        for repo in input_data.ecr.repositories:
            records.append(
                self._ecr_repository(repo, now)
            )

        # ECS Clusters
        for cluster in input_data.ecs.clusters:
            records.append(
                self._ecs_cluster(cluster, now)
            )

        # ECS Task Definitions
        for td in (
            input_data.ecs.task_definitions
        ):
            records.append(
                self._ecs_task_definition(td, now)
            )

        # EKS Clusters
        for eks in input_data.eks.clusters:
            records.append(
                self._eks_cluster(eks, now)
            )

        return records

    def enrich_with_data_classification(
        self,
        records: list[ResourceRecord],
        data_classifier,
        compliance_mapper,
        macie_data=None,
    ) -> None:
        """Enrich records with data classification and
        compliance mapping.

        For each record:
          1. Call data_classifier.classify_resource(...)
          2. Call compliance_mapper.map(classification)
          3. Set record.data_sensitivity, data_types,
             and compliance_gaps.

        Errors for individual resources are logged and
        skipped so one bad resource never aborts the
        whole enrichment pass.

        Args:
            records: ResourceRecord list (mutated).
            data_classifier: DataClassifier instance.
            compliance_mapper: ComplianceMapper instance.
            macie_data: Pre-collected MacieData for S3
                bucket classification priority (optional).
        """
        for rec in records:
            try:
                classification = (
                    data_classifier.classify_resource(
                        resource_type=rec.resource_type,
                        resource_id=rec.resource_id,
                        resource_name=rec.resource_name,
                        tags=rec.tags,
                        macie_data=macie_data,
                    )
                )
                result = compliance_mapper.map(
                    classification
                )
                rec.data_sensitivity = (
                    classification.sensitivity
                )
                rec.data_types = (
                    classification.data_types
                )
                rec.compliance_gaps = (
                    result.compliance_gaps
                )
            except Exception as exc:
                logger.warning(
                    "Data classification failed for "
                    "%s (%s): %s",
                    rec.resource_id,
                    rec.resource_type,
                    exc,
                )

    def enrich_with_violations(
        self,
        records: list[ResourceRecord],
        violations,
    ) -> None:
        """Add violation counts and risk score.

        Only counts violations with status='alarm'.
        Computes an aggregate risk_score (0-100) from
        severity weights: critical=25, high=15,
        medium=8, low=3.

        Args:
            records: Records to enrich (mutated).
            violations: OPA evaluation results.
        """
        alarm_by_res: dict[str, list] = {}
        for v in violations:
            res = getattr(v, "resource", "")
            if (
                getattr(v, "status", "") == "alarm"
                and res
            ):
                alarm_by_res.setdefault(
                    res, []
                ).append(v)

        for rec in records:
            alarms = alarm_by_res.get(
                rec.resource_id, []
            )
            rec.violation_count = len(alarms)
            rec.critical_violations = sum(
                1
                for a in alarms
                if getattr(
                    a, "severity", ""
                ).lower()
                == "critical"
            )
            rec.high_violations = sum(
                1
                for a in alarms
                if getattr(
                    a, "severity", ""
                ).lower()
                == "high"
            )
            rec.risk_score = _compute_risk_score(
                alarms
            )

    # ── Per-type classifiers ───────────────────────

    def _make_record(
        self,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        now: str,
        tags: dict | None = None,
        exposure: str = "private",
        connected_to: list[str] | None = None,
        belongs_to: str | None = None,
        managed_by: str | None = None,
        region_override: str | None = None,
    ) -> ResourceRecord:
        """Build a ResourceRecord with taxonomy.

        Args:
            region_override: Use this region instead of
                self.region. Needed for global services
                like S3 where the bucket's true region
                differs from the scanner loop region.
        """
        tags = tags or {}
        cat, svc = get_taxonomy(resource_type)
        env, owner = extract_env_owner(tags)
        effective_region = region_override or self.region
        return ResourceRecord(
            pk=(
                f"{self.account_id}"
                f"#{effective_region}"
            ),
            sk=f"{resource_type}#{resource_id}",
            resource_id=resource_id,
            resource_name=resource_name,
            resource_type=resource_type,
            technology_category=cat,
            service=svc,
            region=effective_region,
            account_id=self.account_id,
            exposure=exposure,
            tags=tags,
            environment=env,
            owner=owner,
            last_seen=now,
            connected_to=connected_to or [],
            belongs_to=belongs_to,
            managed_by=managed_by,
        )

    def _ec2(self, inst, exposure_clf, now):
        exp = exposure_clf.classify(
            "ec2_instance", inst.instance_id
        )
        return self._make_record(
            "ec2_instance",
            inst.arn,
            inst.instance_id,
            now,
            tags=inst.tags,
            exposure=exp,
            connected_to=[
                sg["group_id"] if isinstance(sg, dict)
                else sg
                for sg in inst.security_groups
            ],
            belongs_to=inst.vpc_id,
            managed_by=(
                inst.iam_role.role_arn
                if inst.iam_role
                else None
            ),
        )

    def _s3(self, bkt, exposure_clf, now):
        exp = exposure_clf.classify(
            "s3_bucket", bkt.name
        )
        return self._make_record(
            "s3_bucket",
            bkt.arn,
            bkt.name,
            now,
            tags=bkt.tags,
            exposure=exp,
            region_override=bkt.region or None,
        )

    def _rds(self, db, exposure_clf, now):
        exp = exposure_clf.classify(
            "rds_instance", db.db_instance_id
        )
        return self._make_record(
            "rds_instance",
            db.arn,
            db.db_instance_id,
            now,
            tags=db.tags,
            exposure=exp,
        )

    def _lambda(self, fn, exposure_clf, now):
        exp = exposure_clf.classify(
            "lambda_function", fn.function_name
        )
        return self._make_record(
            "lambda_function",
            fn.arn,
            fn.function_name,
            now,
            tags=fn.tags,
            exposure=exp,
            managed_by=fn.role or None,
        )

    def _ebs(self, vol, now):
        return self._make_record(
            "ebs_volume",
            vol.arn,
            vol.volume_id,
            now,
            tags=vol.tags,
            exposure="private",
            belongs_to=vol.attached_instance,
        )

    def _sg(self, sg, now):
        return self._make_record(
            "security_group",
            sg.arn,
            sg.group_name or sg.group_id,
            now,
            exposure="private",
            belongs_to=sg.vpc_id or None,
        )

    def _vpc(self, vpc, now):
        arn = (
            f"arn:aws:ec2:{self.region}"
            f":{self.account_id}:vpc/{vpc.vpc_id}"
        )
        return self._make_record(
            "vpc",
            arn,
            vpc.vpc_id,
            now,
            exposure="private",
        )

    def _kms(self, key, now):
        return self._make_record(
            "kms_key",
            key.arn,
            key.key_id,
            now,
            tags=key.tags,
            exposure="private",
        )

    def _secret(self, sec, now):
        return self._make_record(
            "secret",
            sec.arn,
            sec.name,
            now,
            exposure="private",
        )

    def _iam_user(self, user, now):
        return self._make_record(
            "iam_user",
            user.arn,
            user.name,
            now,
            exposure="private",
        )

    def _iam_group(self, grp, now):
        return self._make_record(
            "iam_group",
            grp.arn,
            grp.group_name,
            now,
            exposure="private",
        )

    def _iam_role(self, role, now):
        return self._make_record(
            "iam_role",
            role.arn,
            role.role_name,
            now,
            tags=role.tags,
            exposure="private",
        )

    def _iam_policy(self, pol, now):
        return self._make_record(
            "iam_policy",
            pol.arn,
            pol.policy_name,
            now,
            exposure="private",
        )

    def _cloudtrail(self, trail, now):
        return self._make_record(
            "cloudtrail",
            trail.arn,
            trail.name,
            now,
            exposure="private",
        )

    def _guardduty(self, det, now):
        arn = (
            f"arn:aws:guardduty:{self.region}"
            f":{self.account_id}"
            f":detector/{det.detector_id}"
        )
        return self._make_record(
            "guardduty",
            arn,
            det.detector_id,
            now,
            exposure="private",
        )

    def _cloudwatch_alarm(self, alarm, now):
        arn = (
            f"arn:aws:cloudwatch:{self.region}"
            f":{self.account_id}"
            f":alarm:{alarm.alarm_name}"
        )
        return self._make_record(
            "cloudwatch_alarm",
            arn,
            alarm.alarm_name,
            now,
            exposure="private",
        )

    def _network_acl(self, nacl, now):
        arn = (
            f"arn:aws:ec2:{self.region}"
            f":{self.account_id}"
            f":network-acl/{nacl.nacl_id}"
        )
        return self._make_record(
            "network_acl",
            arn,
            nacl.nacl_id,
            now,
            exposure="private",
            belongs_to=nacl.vpc_id or None,
        )

    def _subnet(self, sub, now):
        exposure = (
            "internet"
            if sub.map_public_ip_on_launch
            else "private"
        )
        return self._make_record(
            "subnet",
            sub.arn,
            sub.subnet_id,
            now,
            tags=sub.tags,
            exposure=exposure,
            belongs_to=sub.vpc_id or None,
        )

    def _internet_gateway(self, igw, now):
        return self._make_record(
            "internet_gateway",
            igw.arn,
            igw.igw_id,
            now,
            tags=igw.tags,
            exposure="internet",
            connected_to=igw.attached_vpcs,
        )

    def _nat_gateway(self, nat, now):
        return self._make_record(
            "nat_gateway",
            nat.arn,
            nat.nat_gateway_id,
            now,
            tags=nat.tags,
            exposure="private",
            belongs_to=nat.vpc_id or None,
        )

    def _network_firewall(self, nf, now):
        return self._make_record(
            "network_firewall",
            nf.arn,
            nf.firewall_name,
            now,
            tags=nf.tags,
            exposure="private",
            belongs_to=nf.vpc_id or None,
        )

    def _waf_web_acl(self, waf, now):
        return self._make_record(
            "waf_web_acl",
            waf.arn,
            waf.name,
            now,
            tags=waf.tags,
            exposure="private",
        )

    def _aurora_cluster(self, ac, now):
        return self._make_record(
            "aurora_cluster",
            ac.arn,
            ac.cluster_id,
            now,
            tags=ac.tags,
            exposure="private",
        )

    def _dynamodb_table(self, tbl, now):
        return self._make_record(
            "dynamodb_table",
            tbl.arn,
            tbl.table_name,
            now,
            tags=tbl.tags,
            exposure="private",
        )

    def _rds_snapshot(self, snap, now):
        restore_ids = snap.attributes.get(
            "restore", []
        )
        exposure = (
            "internet" if "all" in restore_ids
            else "private"
        )
        return self._make_record(
            "rds_snapshot",
            snap.db_snapshot_arn,
            snap.db_snapshot_identifier,
            now,
            tags={},
            exposure=exposure,
        )

    def _load_balancer(self, lb, now):
        exposure = (
            "internet"
            if lb.scheme == "internet-facing"
            else "private"
        )
        return self._make_record(
            "load_balancer",
            lb.arn,
            lb.lb_name,
            now,
            tags=lb.tags,
            exposure=exposure,
            belongs_to=lb.vpc_id or None,
        )

    def _cloudfront(self, dist, now):
        return self._make_record(
            "cloudfront_distribution",
            dist.arn,
            dist.distribution_id,
            now,
            tags=dist.tags,
            exposure="internet",
        )

    def _route53(self, zone, now):
        arn = (
            f"arn:aws:route53:::hostedzone"
            f"/{zone.hosted_zone_id}"
        )
        exposure = (
            "private"
            if zone.is_private
            else "internet"
        )
        return self._make_record(
            "route53_hosted_zone",
            arn,
            zone.name,
            now,
            exposure=exposure,
        )

    def _auto_scaling_group(self, asg, now):
        return self._make_record(
            "auto_scaling_group",
            asg.arn,
            asg.asg_name,
            now,
            tags=asg.tags,
            exposure="private",
        )

    def _ebs_snapshot(self, snap, now):
        exposure = (
            "internet" if snap.is_public
            else "private"
        )
        return self._make_record(
            "ebs_snapshot",
            snap.arn,
            snap.snapshot_id,
            now,
            tags=snap.tags,
            exposure=exposure,
        )

    def _api_gateway(self, api, now):
        ec = getattr(api, "endpoint_configuration", None)
        types = ec.types if ec else []
        exposure = (
            "private" if "PRIVATE" in types
            else "internet"
        )
        return self._make_record(
            "api_gateway",
            api.arn,
            api.name,
            now,
            tags=api.tags,
            exposure=exposure,
        )

    def _ecr_repository(self, repo, now):
        return self._make_record(
            "ecr_repository",
            repo.arn,
            repo.repository_name,
            now,
            tags=repo.tags,
            exposure="private",
        )

    def _ecs_cluster(self, cluster, now):
        return self._make_record(
            "ecs_cluster",
            cluster.cluster_arn,
            cluster.cluster_name,
            now,
            tags=cluster.tags,
            exposure="private",
        )

    def _ecs_task_definition(self, td, now):
        return self._make_record(
            "ecs_task_definition",
            td.arn,
            td.family,
            now,
            tags=td.tags,
            exposure="private",
        )

    def _eks_cluster(self, eks, now):
        public = (
            eks.resources_vpc_config
            .endpoint_public_access
        )
        exposure = "internet" if public else "private"
        return self._make_record(
            "eks_cluster",
            eks.arn,
            eks.name,
            now,
            tags=eks.tags,
            exposure=exposure,
        )
