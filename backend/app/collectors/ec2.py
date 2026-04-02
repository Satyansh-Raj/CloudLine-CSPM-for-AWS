"""EC2, Security Groups, and EBS collector."""

import logging
from datetime import datetime, timezone

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
            "snapshots": (
                self._get_ebs_snapshots(ec2)
            ),
            "elastic_ips": (
                self._get_elastic_ips(ec2)
            ),
            "amis": self._get_amis(ec2),
            "default_vpc_id": (
                self._get_default_vpc_id(ec2)
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

        # Security groups — list of objects
        sg_list = [
            {
                "group_id": sg.get(
                    "GroupId", ""
                ),
                "group_name": sg.get(
                    "GroupName", ""
                ),
            }
            for sg in inst.get(
                "SecurityGroups", []
            )
        ]

        # IAM instance profile
        iam_instance_profile = None
        profile = inst.get("IamInstanceProfile")
        if profile:
            iam_instance_profile = {
                "role_name": profile.get(
                    "Arn", ""
                ).split("/")[-1],
                "role_arn": profile.get(
                    "Arn", ""
                ),
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

        # Monitoring
        monitoring_raw = inst.get(
            "Monitoring", {}
        )
        monitoring = {
            "state": monitoring_raw.get(
                "State", "disabled"
            ),
        }

        # Tags
        tags = {
            t["Key"]: t["Value"]
            for t in inst.get("Tags", [])
        }

        # Block device mappings
        block_device_mappings = []
        for bdm in inst.get(
            "BlockDeviceMappings", []
        ):
            ebs_info = bdm.get("Ebs", {})
            block_device_mappings.append({
                "device_name": bdm.get(
                    "DeviceName", ""
                ),
                "ebs": {
                    "volume_id": ebs_info.get(
                        "VolumeId", ""
                    ),
                    "status": ebs_info.get(
                        "Status", ""
                    ),
                    "encrypted": (
                        self._get_volume_encrypted(
                            ec2,
                            ebs_info.get(
                                "VolumeId", ""
                            ),
                        )
                    ),
                },
            })

        # Termination protection
        disable_api_termination = (
            self._get_termination_protection(
                ec2, iid
            )
        )

        # State as object with name field
        state = {
            "name": inst["State"]["Name"],
            "code": inst["State"].get("Code", 0),
        }

        # Compute days_since_stopped
        days_since_stopped = (
            self._compute_days_since_stopped(
                inst
            )
        )

        return {
            "instance_id": iid,
            "arn": arn,
            "state": state,
            "instance_type": inst.get(
                "InstanceType", ""
            ),
            "key_name": inst.get(
                "KeyName"
            ),
            "public_ip_address": inst.get(
                "PublicIpAddress"
            ),
            "private_ip_address": inst.get(
                "PrivateIpAddress"
            ),
            "subnet_id": inst.get("SubnetId"),
            "vpc_id": inst.get("VpcId"),
            "security_groups": sg_list,
            "iam_instance_profile": (
                iam_instance_profile
            ),
            "metadata_options": metadata_options,
            "monitoring": monitoring,
            "block_device_mappings": (
                block_device_mappings
            ),
            "root_device_name": inst.get(
                "RootDeviceName", ""
            ),
            "disable_api_termination": (
                disable_api_termination
            ),
            "days_since_stopped": (
                days_since_stopped
            ),
            "tags": tags,
        }

    def _get_volume_encrypted(
        self, ec2, volume_id: str
    ) -> bool:
        """Check if an EBS volume is encrypted."""
        if not volume_id:
            return False
        try:
            resp = ec2.describe_volumes(
                VolumeIds=[volume_id]
            )
            vols = resp.get("Volumes", [])
            if vols:
                return vols[0].get(
                    "Encrypted", False
                )
        except Exception as e:
            logger.error(
                "EC2 volume encrypted check "
                "%s: %s",
                volume_id,
                e,
            )
        return False

    def _get_termination_protection(
        self, ec2, instance_id: str
    ) -> bool:
        """Check if termination protection is
        disabled for an instance.

        Returns False (protection disabled) when
        the attribute is False or on error."""
        try:
            resp = ec2.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute="disableApiTermination",
            )
            val = resp.get(
                "DisableApiTermination", {}
            )
            return val.get("Value", False)
        except Exception as e:
            logger.error(
                "EC2 termination protection "
                "%s: %s",
                instance_id,
                e,
            )
        return False

    def _compute_days_since_stopped(
        self, inst: dict
    ) -> int | None:
        """Compute days since instance was stopped.

        Uses StateTransitionReason which contains
        the stop timestamp. Returns None if the
        instance is not stopped or the timestamp
        cannot be parsed."""
        state_name = inst["State"]["Name"]
        if state_name != "stopped":
            return None
        reason = inst.get(
            "StateTransitionReason", ""
        )
        # Format: "User initiated (YYYY-MM-DD ...)"
        try:
            if "(" in reason and ")" in reason:
                ts_str = reason.split("(")[1]
                ts_str = ts_str.rstrip(")")
                ts_str = ts_str.strip()
                stopped_at = datetime.strptime(
                    ts_str, "%Y-%m-%d %H:%M:%S %Z"
                ).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = now - stopped_at
                return delta.days
        except Exception as e:
            logger.error(
                "EC2 days_since_stopped parse "
                "%s: %s",
                inst["InstanceId"],
                e,
            )
        return 0

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
        ip_permissions = self._build_ip_permissions(
            sg.get("IpPermissions", [])
        )
        ip_permissions_egress = (
            self._build_ip_permissions(
                sg.get("IpPermissionsEgress", [])
            )
        )

        sg_id = sg["GroupId"]
        region = self._region
        account = self._get_account_id()
        arn = (
            f"arn:aws:ec2:{region}:{account}"
            f":security-group/{sg_id}"
        )

        tags = {
            t["Key"]: t["Value"]
            for t in sg.get("Tags", [])
        }

        return {
            "group_id": sg_id,
            "group_name": sg.get(
                "GroupName", ""
            ),
            "arn": arn,
            "vpc_id": sg.get("VpcId", ""),
            "ip_permissions": ip_permissions,
            "ip_permissions_egress": (
                ip_permissions_egress
            ),
            "tags": tags,
        }

    def _build_ip_permissions(
        self, perms: list[dict]
    ) -> list[dict]:
        """Convert boto3 IpPermissions list to the
        format expected by OPA Rego policies.

        Each permission has: from_port, to_port,
        ip_protocol, ip_ranges, ipv6_ranges."""
        result = []
        for perm in perms:
            from_port = perm.get("FromPort", -1)
            to_port = perm.get("ToPort", -1)
            protocol = perm.get(
                "IpProtocol", "-1"
            )

            ip_ranges = [
                {
                    "cidr_ip": r.get(
                        "CidrIp", ""
                    ),
                    "description": r.get(
                        "Description", ""
                    ),
                }
                for r in perm.get(
                    "IpRanges", []
                )
            ]

            ipv6_ranges = [
                {
                    "cidr_ipv6": r.get(
                        "CidrIpv6", ""
                    ),
                    "description": r.get(
                        "Description", ""
                    ),
                }
                for r in perm.get(
                    "Ipv6Ranges", []
                )
            ]

            result.append({
                "from_port": from_port,
                "to_port": to_port,
                "ip_protocol": protocol,
                "ip_ranges": ip_ranges,
                "ipv6_ranges": ipv6_ranges,
            })
        return result

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
                    # Get volume permissions
                    create_volume_permissions = (
                        self._get_snapshot_perms(
                            ec2, sid
                        )
                    )
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
                            "is_public": any(
                                p.get("group") == "all"
                                for p in create_volume_permissions
                            ),
                            "create_volume_permissions": (
                                create_volume_permissions
                            ),
                            "tags": snap_tags,
                        }
                    )
        except Exception as e:
            logger.error(
                "EC2 describe_snapshots: %s", e
            )
        return snapshots

    def _get_snapshot_perms(
        self, ec2, snapshot_id: str
    ) -> list[dict]:
        """Fetch create-volume permissions for a
        snapshot. Returns list of permission dicts
        with 'group' and/or 'user_id' keys."""
        try:
            attr = (
                ec2.describe_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute=(
                        "createVolumePermission"
                    ),
                )
            )
            raw_perms = attr.get(
                "CreateVolumePermissions", []
            )
            return [
                {
                    "group": p.get("Group"),
                    "user_id": p.get("UserId"),
                }
                for p in raw_perms
            ]
        except Exception as e:
            logger.error(
                "EC2 snapshot permissions "
                "%s: %s",
                snapshot_id,
                e,
            )
        return []

    def _get_elastic_ips(
        self, ec2
    ) -> list[dict]:
        """Collect Elastic IP addresses."""
        eips = []
        try:
            resp = ec2.describe_addresses()
            for addr in resp.get(
                "Addresses", []
            ):
                alloc_id = addr.get(
                    "AllocationId", ""
                )
                region = self._region
                account = self._get_account_id()
                arn = (
                    f"arn:aws:ec2:{region}"
                    f":{account}"
                    f":elastic-ip/{alloc_id}"
                )
                tags = {
                    t["Key"]: t["Value"]
                    for t in addr.get("Tags", [])
                }
                eips.append({
                    "allocation_id": alloc_id,
                    "public_ip": addr.get(
                        "PublicIp", ""
                    ),
                    "instance_id": addr.get(
                        "InstanceId"
                    ),
                    "network_interface_id": (
                        addr.get(
                            "NetworkInterfaceId"
                        )
                    ),
                    "association_id": addr.get(
                        "AssociationId"
                    ),
                    "arn": arn,
                    "tags": tags,
                })
        except Exception as e:
            logger.error(
                "EC2 describe_addresses: %s", e
            )
        return eips

    def _get_amis(self, ec2) -> list[dict]:
        """Collect AMIs owned by this account."""
        amis = []
        try:
            resp = ec2.describe_images(
                Owners=["self"]
            )
            for img in resp.get("Images", []):
                image_id = img.get("ImageId", "")
                region = self._region
                account = self._get_account_id()
                arn = (
                    f"arn:aws:ec2:{region}"
                    f":{account}"
                    f":image/{image_id}"
                )
                tags = {
                    t["Key"]: t["Value"]
                    for t in img.get("Tags", [])
                }
                amis.append({
                    "image_id": image_id,
                    "arn": arn,
                    "name": img.get("Name", ""),
                    "owner_id": img.get(
                        "OwnerId", ""
                    ),
                    "public": img.get(
                        "Public", False
                    ),
                    "state": img.get(
                        "State", ""
                    ),
                    "tags": tags,
                })
        except Exception as e:
            logger.error(
                "EC2 describe_images: %s", e
            )
        return amis

    def _get_default_vpc_id(
        self, ec2
    ) -> str | None:
        """Find the default VPC ID for this
        region, or None if there is none."""
        try:
            resp = ec2.describe_vpcs(
                Filters=[
                    {
                        "Name": "is-default",
                        "Values": ["true"],
                    }
                ]
            )
            vpcs = resp.get("Vpcs", [])
            if vpcs:
                return vpcs[0].get("VpcId")
        except Exception as e:
            logger.error(
                "EC2 default VPC lookup: %s", e
            )
        return None
