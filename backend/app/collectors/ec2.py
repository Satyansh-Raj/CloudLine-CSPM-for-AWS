"""EC2, Security Groups, and EBS collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class EC2Collector(BaseCollector):
    """Collects EC2 instances, security groups,
    and EBS volumes."""

    def __init__(self, session, account_id="",
                 region=""):
        super().__init__(session)
        self._account_id = account_id
        self._region = region or (
            session.region_name or ""
        )

    def _get_account_id(self):
        """Return cached account_id, fetching via
        STS only once if not provided."""
        if not self._account_id:
            try:
                sts = self.session.client("sts")
                self._account_id = (
                    sts.get_caller_identity()[
                        "Account"
                    ]
                )
            except Exception:
                pass
        return self._account_id

    def collect(self) -> tuple[str, dict]:
        ec2 = self.session.client("ec2")
        asg_client = self.session.client(
            "autoscaling"
        )
        return "ec2", {
            "instances": self._get_instances(ec2),
            "security_groups": (
                self._get_security_groups(ec2)
            ),
            "ebs_volumes": self._get_ebs_volumes(
                ec2
            ),
            "auto_scaling_groups": (
                self._get_auto_scaling_groups(
                    asg_client
                )
            ),
            "ebs_snapshots": (
                self._get_ebs_snapshots(ec2)
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        ec2 = self.session.client("ec2")
        if resource_id.startswith("i-"):
            instances = self._get_instances(
                ec2, [resource_id]
            )
            return instances[0] if instances else {}
        if resource_id.startswith("sg-"):
            sgs = self._get_security_groups(
                ec2, [resource_id]
            )
            return sgs[0] if sgs else {}
        if resource_id.startswith("vol-"):
            vols = self._get_ebs_volumes(
                ec2, [resource_id]
            )
            return vols[0] if vols else {}
        if resource_id.startswith("snap-"):
            snaps = self._get_ebs_snapshots(
                ec2, [resource_id]
            )
            return snaps[0] if snaps else {}
        return {}

    def _get_instances(
        self, ec2, instance_ids: list | None = None
    ) -> list[dict]:
        instances = []
        try:
            kwargs = {}
            if instance_ids:
                kwargs["InstanceIds"] = instance_ids
            paginator = ec2.get_paginator(
                "describe_instances"
            )
            for page in paginator.paginate(**kwargs):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        instances.append(
                            self._build_instance(
                                ec2, inst
                            )
                        )
        except Exception as e:
            logger.error(
                "EC2 describe_instances: %s", e
            )
        return instances

    def _build_instance(
        self, ec2, inst: dict
    ) -> dict:
        iid = inst["InstanceId"]
        region = self._region
        account = self._get_account_id()

        arn = (
            f"arn:aws:ec2:{region}:{account}"
            f":instance/{iid}"
        )

        # Security groups
        sg_ids = [
            sg["GroupId"]
            for sg in inst.get(
                "SecurityGroups", []
            )
        ]

        # IAM role
        iam_role = None
        profile = inst.get("IamInstanceProfile")
        if profile:
            iam_role = {
                "role_name": profile.get(
                    "Arn", ""
                ).split("/")[-1],
                "role_arn": profile.get("Arn", ""),
                "attached_policies": [],
            }

        # Metadata options
        meta = inst.get("MetadataOptions", {})
        metadata_options = {
            "http_tokens": meta.get(
                "HttpTokens", "optional"
            ),
            "http_endpoint": meta.get(
                "HttpEndpoint", "enabled"
            ),
        }

        # Tags
        tags = {
            t["Key"]: t["Value"]
            for t in inst.get("Tags", [])
        }

        return {
            "instance_id": iid,
            "arn": arn,
            "state": inst["State"]["Name"],
            "public_ip": inst.get(
                "PublicIpAddress"
            ),
            "private_ip": inst.get(
                "PrivateIpAddress"
            ),
            "subnet_id": inst.get("SubnetId"),
            "vpc_id": inst.get("VpcId"),
            "security_groups": sg_ids,
            "iam_role": iam_role,
            "metadata_options": metadata_options,
            "tags": tags,
        }

    def _get_security_groups(
        self,
        ec2,
        group_ids: list | None = None,
    ) -> list[dict]:
        sgs = []
        try:
            kwargs = {}
            if group_ids:
                kwargs["GroupIds"] = group_ids
            paginator = ec2.get_paginator(
                "describe_security_groups"
            )
            for page in paginator.paginate(
                **kwargs
            ):
                for sg in page["SecurityGroups"]:
                    sgs.append(
                        self._build_security_group(
                            sg
                        )
                    )
        except Exception as e:
            logger.error(
                "EC2 describe_security_groups: %s",
                e,
            )
        return sgs

    def _build_security_group(
        self, sg: dict
    ) -> dict:
        ingress_rules = []
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort", -1)
            to_port = perm.get("ToPort", -1)
            protocol = perm.get(
                "IpProtocol", "-1"
            )
            for ip_range in perm.get(
                "IpRanges", []
            ):
                ingress_rules.append(
                    {
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": protocol,
                        "cidr": ip_range.get(
                            "CidrIp", ""
                        ),
                        "description": ip_range.get(
                            "Description", ""
                        ),
                    }
                )
            for ip_range in perm.get(
                "Ipv6Ranges", []
            ):
                ingress_rules.append(
                    {
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": protocol,
                        "cidr": ip_range.get(
                            "CidrIpv6", ""
                        ),
                        "description": ip_range.get(
                            "Description", ""
                        ),
                    }
                )
        sg_id = sg["GroupId"]
        region = self._region
        account = self._get_account_id()
        arn = (
            f"arn:aws:ec2:{region}:{account}"
            f":security-group/{sg_id}"
        )
        return {
            "group_id": sg_id,
            "group_name": sg.get(
                "GroupName", ""
            ),
            "arn": arn,
            "vpc_id": sg.get("VpcId", ""),
            "ingress_rules": ingress_rules,
        }

    def _get_ebs_volumes(
        self,
        ec2,
        volume_ids: list | None = None,
    ) -> list[dict]:
        volumes = []
        try:
            kwargs = {}
            if volume_ids:
                kwargs["VolumeIds"] = volume_ids
            paginator = ec2.get_paginator(
                "describe_volumes"
            )
            for page in paginator.paginate(
                **kwargs
            ):
                for vol in page["Volumes"]:
                    attached = ""
                    if vol.get("Attachments"):
                        attached = vol[
                            "Attachments"
                        ][0].get("InstanceId", "")
                    vol_id = vol["VolumeId"]
                    region = self._region
                    account = (
                        self._get_account_id()
                    )
                    arn = (
                        f"arn:aws:ec2:{region}"
                        f":{account}"
                        f":volume/{vol_id}"
                    )
                    vol_tags = {
                        t["Key"]: t["Value"]
                        for t in vol.get("Tags", [])
                    }
                    volumes.append(
                        {
                            "volume_id": vol_id,
                            "arn": arn,
                            "encrypted": vol.get(
                                "Encrypted",
                                False,
                            ),
                            "size_gb": vol.get(
                                "Size", 0
                            ),
                            "state": vol.get(
                                "State", ""
                            ),
                            "attached_instance": (
                                attached or None
                            ),
                            "tags": vol_tags,
                        }
                    )
        except Exception as e:
            logger.error(
                "EC2 describe_volumes: %s", e
            )
        return volumes

    def _get_auto_scaling_groups(
        self, asg_client
    ) -> list[dict]:
        groups = []
        try:
            paginator = asg_client.get_paginator(
                "describe_auto_scaling_groups"
            )
            for page in paginator.paginate():
                for g in page[
                    "AutoScalingGroups"
                ]:
                    tags = {
                        t["Key"]: t["Value"]
                        for t in g.get("Tags", [])
                    }
                    groups.append(
                        {
                            "asg_name": g[
                                "AutoScalingGroupName"
                            ],
                            "arn": g.get(
                                "AutoScalingGroupARN",
                                "",
                            ),
                            "min_size": g.get(
                                "MinSize", 0
                            ),
                            "max_size": g.get(
                                "MaxSize", 0
                            ),
                            "desired_capacity": (
                                g.get(
                                    "DesiredCapacity",
                                    0,
                                )
                            ),
                            "launch_template": (
                                g.get(
                                    "LaunchTemplate",
                                    {},
                                ).get(
                                    "LaunchTemplateName",
                                    "",
                                )
                            ),
                            "vpc_zone_ids": (
                                g.get(
                                    "VPCZoneIdentifier",
                                    "",
                                ).split(",")
                                if g.get(
                                    "VPCZoneIdentifier"
                                )
                                else []
                            ),
                            "tags": tags,
                        }
                    )
        except Exception as e:
            logger.error(
                "ASG describe: %s", e
            )
        return groups

    def _get_ebs_snapshots(
        self,
        ec2,
        snapshot_ids: list | None = None,
    ) -> list[dict]:
        snapshots = []
        try:
            kwargs = {"OwnerIds": ["self"]}
            if snapshot_ids:
                kwargs["SnapshotIds"] = snapshot_ids
            paginator = ec2.get_paginator(
                "describe_snapshots"
            )
            for page in paginator.paginate(
                **kwargs
            ):
                for snap in page["Snapshots"]:
                    sid = snap["SnapshotId"]
                    region = self._region
                    account = (
                        self._get_account_id()
                    )
                    arn = (
                        f"arn:aws:ec2:{region}"
                        f":{account}"
                        f":snapshot/{sid}"
                    )
                    snap_tags = {
                        t["Key"]: t["Value"]
                        for t in snap.get(
                            "Tags", []
                        )
                    }
                    # Check if public
                    is_public = False
                    try:
                        attr = (
                            ec2
                            .describe_snapshot_attribute(
                                SnapshotId=sid,
                                Attribute=(
                                    "createVolumePermission"
                                ),
                            )
                        )
                        perms = attr.get(
                            "CreateVolumePermissions",
                            [],
                        )
                        is_public = any(
                            p.get("Group") == "all"
                            for p in perms
                        )
                    except Exception:
                        pass
                    snapshots.append(
                        {
                            "snapshot_id": sid,
                            "arn": arn,
                            "volume_id": snap.get(
                                "VolumeId", ""
                            ),
                            "encrypted": snap.get(
                                "Encrypted",
                                False,
                            ),
                            "is_public": is_public,
                            "tags": snap_tags,
                        }
                    )
        except Exception as e:
            logger.error(
                "EC2 describe_snapshots: %s", e
            )
        return snapshots
