"""Graph-path exposure classifier.

Determines internet exposure by walking the network
path for each resource type:

  EC2: public_ip → SG allows 0.0.0.0/0 → NACL allows
  S3:  all 4 public_access_block flags must be True
  RDS: publicly_accessible flag
  Lambda: absent VPC config = internet (default)

NACL rules are evaluated in rule_number order (lowest
first). First matching rule wins. If no NACL exists for
the VPC, AWS default allows all (we mirror that).
"""

import logging

from app.models.aws_input import (
    EC2Instance,
    LambdaFunction,
    NACL,
    RDSInstance,
    S3Bucket,
    SecurityGroup,
    UnifiedAWSInput,
)

logger = logging.getLogger(__name__)

# CIDRs that represent "any source" (internet).
_ANY_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


class ExposureClassifier:
    """Classifies resource internet exposure via
    network graph-path analysis.

    Attributes:
        _sg_by_id: SG lookup by group_id.
        _nacls_by_vpc: NACLs grouped by vpc_id.
        _ec2_by_id: EC2 instances by instance_id.
        _s3_by_name: S3 buckets by name.
        _rds_by_id: RDS instances by db_instance_id.
        _lambda_by_name: Lambda functions by name.
    """

    def __init__(
        self, input_data: UnifiedAWSInput
    ):
        # SG index
        self._sg_by_id: dict[str, SecurityGroup] = {
            sg.group_id: sg
            for sg in input_data.ec2.security_groups
        }

        # NACLs grouped by VPC
        self._nacls_by_vpc: dict[str, list[NACL]] = {}
        for nacl in input_data.vpc.nacls:
            self._nacls_by_vpc.setdefault(
                nacl.vpc_id, []
            ).append(nacl)

        # Resource indexes for dispatch
        self._ec2_by_id = {
            i.instance_id: i
            for i in input_data.ec2.instances
        }
        self._s3_by_name = {
            b.name: b
            for b in input_data.s3.buckets
        }
        self._rds_by_id = {
            d.db_instance_id: d
            for d in input_data.rds.db_instances
        }
        self._lambda_by_name = {
            f.function_name: f
            for f in input_data.lambda_functions
        }

    # ------------------------------------------
    # Public API
    # ------------------------------------------

    def classify(
        self, resource_type: str, resource_id: str
    ) -> str:
        """Classify exposure for any resource.

        Args:
            resource_type: Normalized type
                (ec2_instance, s3_bucket, etc.).
            resource_id: Instance ID, bucket name,
                DB ID, or function name.

        Returns:
            'internet' | 'private' | 'unknown'
        """
        if resource_type == "ec2_instance":
            inst = self._ec2_by_id.get(
                resource_id
            )
            if not inst:
                return "unknown"
            return self.classify_ec2(inst)

        if resource_type == "s3_bucket":
            bucket = self._s3_by_name.get(
                resource_id
            )
            if not bucket:
                return "unknown"
            return self.classify_s3(bucket)

        if resource_type == "rds_instance":
            db = self._rds_by_id.get(resource_id)
            if not db:
                return "unknown"
            return self.classify_rds(db)

        if resource_type == "lambda_function":
            fn = self._lambda_by_name.get(
                resource_id
            )
            if not fn:
                return "unknown"
            return self.classify_lambda(fn)

        return "unknown"

    # ------------------------------------------
    # Per-resource classifiers
    # ------------------------------------------

    def classify_ec2(
        self, instance: EC2Instance
    ) -> str:
        """EC2 exposure via network graph path.

        Path: public_ip → SG ingress → NACL inbound.
        All three must be open for 'internet'.
        """
        # Step 1: must have a public IP
        if not instance.public_ip_address:
            return "private"

        # Step 2: must have a VPC to evaluate
        if not instance.vpc_id:
            return "unknown"

        # Step 3: at least one SG must allow
        #         0.0.0.0/0 or ::/0 ingress
        sg_ids = [
            sg["group_id"] if isinstance(sg, dict)
            else sg
            for sg in instance.security_groups
        ]
        sg_result = self._sg_allows_any(sg_ids)
        if sg_result is None:
            return "unknown"
        if not sg_result:
            return "private"

        # Step 4: NACL must allow inbound from
        #         0.0.0.0/0 (or no NACL = default allow)
        if not self._nacl_allows_inbound(
            instance.vpc_id
        ):
            return "private"

        return "internet"

    def classify_s3(self, bucket: S3Bucket) -> str:
        """S3 exposure via public_access_block.

        All 4 flags must be True for 'private'.
        Any False flag means potentially internet-facing.
        """
        pab = bucket.public_access_block
        if (
            pab.block_public_acls
            and pab.block_public_policy
            and pab.ignore_public_acls
            and pab.restrict_public_buckets
        ):
            return "private"
        return "internet"

    def classify_rds(self, db: RDSInstance) -> str:
        """RDS exposure via publicly_accessible."""
        if db.publicly_accessible:
            return "internet"
        return "private"

    def classify_lambda(
        self, fn: LambdaFunction
    ) -> str:
        """Lambda exposure via VPC config.

        Lambda not in VPC has internet access by
        default. Lambda in VPC requires a NAT Gateway
        for internet — we conservatively mark it
        private.
        """
        vpc = fn.vpc_config
        if vpc.subnet_ids or vpc.security_group_ids:
            return "private"
        return "internet"

    # ------------------------------------------
    # Internal helpers
    # ------------------------------------------

    def _sg_allows_any(
        self, sg_ids: list[str]
    ) -> bool | None:
        """Check if ANY SG allows ingress from
        0.0.0.0/0 or ::/0.

        Returns:
            True: at least one SG allows any-source.
            False: all SGs restrict to specific CIDRs.
            None: no referenced SGs found in data.
        """
        found = False
        for sg_id in sg_ids:
            sg = self._sg_by_id.get(sg_id)
            if not sg:
                continue
            found = True
            for rule in sg.ingress_rules:
                if rule.cidr in _ANY_CIDRS:
                    return True
        if not found:
            return None
        return False

    def _nacl_allows_inbound(
        self, vpc_id: str
    ) -> bool:
        """Check if the VPC's NACLs allow inbound
        from 0.0.0.0/0 or ::/0.

        NACL rules are stateless and evaluated in
        rule_number order (lowest first). First
        matching rule wins.

        If no NACLs exist for the VPC, AWS default
        behavior is to allow all traffic.
        """
        nacls = self._nacls_by_vpc.get(vpc_id)
        if not nacls:
            return True  # No NACL = AWS default allow

        for nacl in nacls:
            # Filter ingress rules only
            ingress = [
                e
                for e in nacl.entries
                if not e.egress
            ]
            # Sort by rule_number (lowest first)
            ingress.sort(
                key=lambda e: e.rule_number
            )
            for entry in ingress:
                if entry.cidr_block in _ANY_CIDRS:
                    return (
                        entry.rule_action == "allow"
                    )
        return False
