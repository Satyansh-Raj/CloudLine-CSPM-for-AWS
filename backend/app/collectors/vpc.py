"""VPC, Flow Logs, and NACL collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class VPCCollector(BaseCollector):
    """Collects VPCs, VPC Flow Logs, and Network ACLs."""

    def collect(self) -> tuple[str, dict]:
        ec2 = self.session.client("ec2")
        return "vpc", {
            "vpcs": self._get_vpcs(ec2),
            "flow_logs": self._get_flow_logs(ec2),
            "nacls": self._get_nacls(ec2),
            "subnets": self._get_subnets(ec2),
            "internet_gateways": (
                self._get_internet_gateways(ec2)
            ),
            "nat_gateways": (
                self._get_nat_gateways(ec2)
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        ec2 = self.session.client("ec2")
        if resource_id.startswith("vpc-"):
            vpcs = self._get_vpcs(
                ec2, [resource_id]
            )
            return vpcs[0] if vpcs else {}
        return {}

    def _get_vpcs(
        self,
        ec2,
        vpc_ids: list | None = None,
    ) -> list[dict]:
        vpcs = []
        try:
            kwargs = {}
            if vpc_ids:
                kwargs["VpcIds"] = vpc_ids
            resp = ec2.describe_vpcs(**kwargs)
            for v in resp["Vpcs"]:
                vpcs.append(
                    {
                        "vpc_id": v["VpcId"],
                        "cidr_block": v.get(
                            "CidrBlock", ""
                        ),
                        "is_default": v.get(
                            "IsDefault", False
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_vpcs: %s", e
            )
        return vpcs

    def _get_flow_logs(
        self,
        ec2,
        resource_ids: list | None = None,
    ) -> list[dict]:
        flow_logs = []
        try:
            kwargs = {}
            if resource_ids:
                kwargs["Filters"] = [
                    {
                        "Name": "resource-id",
                        "Values": resource_ids,
                    }
                ]
            resp = ec2.describe_flow_logs(**kwargs)
            for fl in resp.get("FlowLogs", []):
                flow_logs.append(
                    {
                        "flow_log_id": fl[
                            "FlowLogId"
                        ],
                        "resource_id": fl.get(
                            "ResourceId", ""
                        ),
                        "traffic_type": fl.get(
                            "TrafficType", "ALL"
                        ),
                        "status": fl.get(
                            "FlowLogStatus",
                            "ACTIVE",
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_flow_logs: %s", e
            )
        return flow_logs

    def _get_nacls(
        self,
        ec2,
        nacl_ids: list | None = None,
    ) -> list[dict]:
        nacls = []
        try:
            kwargs = {}
            if nacl_ids:
                kwargs["NetworkAclIds"] = nacl_ids
            resp = ec2.describe_network_acls(
                **kwargs
            )
            for nacl in resp["NetworkAcls"]:
                entries = []
                for e in nacl.get("Entries", []):
                    cidr = e.get(
                        "CidrBlock",
                        e.get(
                            "Ipv6CidrBlock",
                            "",
                        ),
                    )
                    entries.append(
                        {
                            "rule_number": e.get(
                                "RuleNumber", 0
                            ),
                            "protocol": e.get(
                                "Protocol",
                                "-1",
                            ),
                            "cidr_block": cidr,
                            "rule_action": e.get(
                                "RuleAction",
                                "allow",
                            ),
                            "egress": e.get(
                                "Egress",
                                False,
                            ),
                        }
                    )
                nacls.append(
                    {
                        "nacl_id": nacl[
                            "NetworkAclId"
                        ],
                        "vpc_id": nacl.get(
                            "VpcId", ""
                        ),
                        "entries": entries,
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_network_acls: %s", e
            )
        return nacls

    def _get_subnets(self, ec2) -> list[dict]:
        subnets = []
        try:
            resp = ec2.describe_subnets()
            for s in resp.get("Subnets", []):
                tags = {
                    t["Key"]: t["Value"]
                    for t in s.get("Tags", [])
                }
                subnets.append(
                    {
                        "subnet_id": s["SubnetId"],
                        "arn": s.get(
                            "SubnetArn", ""
                        ),
                        "vpc_id": s.get(
                            "VpcId", ""
                        ),
                        "cidr_block": s.get(
                            "CidrBlock", ""
                        ),
                        "availability_zone": s.get(
                            "AvailabilityZone", ""
                        ),
                        "map_public_ip_on_launch": (
                            s.get(
                                "MapPublicIpOnLaunch",
                                False,
                            )
                        ),
                        "tags": tags,
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_subnets: %s", e
            )
        return subnets

    def _get_internet_gateways(
        self, ec2
    ) -> list[dict]:
        igws = []
        try:
            resp = ec2.describe_internet_gateways()
            for igw in resp.get(
                "InternetGateways", []
            ):
                attached = [
                    a["VpcId"]
                    for a in igw.get(
                        "Attachments", []
                    )
                    if a.get("State") == "available"
                ]
                tags = {
                    t["Key"]: t["Value"]
                    for t in igw.get("Tags", [])
                }
                igws.append(
                    {
                        "igw_id": igw[
                            "InternetGatewayId"
                        ],
                        "arn": "",
                        "attached_vpcs": attached,
                        "tags": tags,
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_igws: %s", e
            )
        return igws

    def _get_nat_gateways(
        self, ec2
    ) -> list[dict]:
        nats = []
        try:
            resp = ec2.describe_nat_gateways()
            for n in resp.get(
                "NatGateways", []
            ):
                tags = {
                    t["Key"]: t["Value"]
                    for t in n.get("Tags", [])
                }
                nats.append(
                    {
                        "nat_gateway_id": n[
                            "NatGatewayId"
                        ],
                        "arn": "",
                        "vpc_id": n.get(
                            "VpcId", ""
                        ),
                        "subnet_id": n.get(
                            "SubnetId", ""
                        ),
                        "state": n.get(
                            "State", "available"
                        ),
                        "tags": tags,
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_nat_gateways: %s", e
            )
        return nats
