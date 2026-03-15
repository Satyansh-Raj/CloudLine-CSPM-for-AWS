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
