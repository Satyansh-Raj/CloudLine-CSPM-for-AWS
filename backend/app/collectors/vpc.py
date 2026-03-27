"""VPC, Flow Logs, and NACL collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class VPCCollector(BaseCollector):
    """Collects VPCs, VPC Flow Logs, Network ACLs,
    Security Groups, Route Tables, Peering Connections,
    and Transit Gateways."""

    def collect(self) -> tuple[str, dict]:
        ec2 = self.session.client("ec2")

        flow_logs = self._get_flow_logs(ec2)
        subnets = self._get_subnets_raw(ec2)
        igws = self._get_internet_gateways(ec2)
        nat_gws = self._get_nat_gateways(ec2)
        route_tables = self._get_route_tables(ec2)

        # Build lookup sets for VPC enrichment
        flow_log_vpc_ids = {
            fl["resource_id"]
            for fl in flow_logs
        }
        igw_vpc_ids = set()
        for igw in igws:
            for vid in igw.get("attached_vpcs", []):
                igw_vpc_ids.add(vid)
        nat_vpc_ids = {
            n["vpc_id"] for n in nat_gws
        }

        # Build subnet AZ map and type map per VPC
        vpc_azs: dict[str, set] = {}
        vpc_has_private: dict[str, bool] = {}
        for s in subnets:
            vid = s.get("vpc_id", "")
            az = s.get("availability_zone", "")
            if vid and az:
                vpc_azs.setdefault(vid, set())
                vpc_azs[vid].add(az)

        # Determine subnet types using route tables
        subnet_rt_type = (
            self._build_subnet_type_map(
                route_tables, igws
            )
        )

        # Classify subnets and track private per VPC
        classified_subnets = []
        for s in subnets:
            sid = s["subnet_id"]
            stype = subnet_rt_type.get(sid)
            if stype is None:
                # Fallback: public if auto-assigns IP
                stype = (
                    "public"
                    if s.get(
                        "map_public_ip_on_launch",
                        False,
                    )
                    else "private"
                )
            classified_subnets.append(
                {
                    "subnet_id": sid,
                    "subnet_type": stype,
                    "map_public_ip_on_launch": s.get(
                        "map_public_ip_on_launch",
                        False,
                    ),
                    "vpc_id": s.get("vpc_id", ""),
                }
            )
            vid = s.get("vpc_id", "")
            if stype == "private" and vid:
                vpc_has_private[vid] = True

        # Classify route tables with subnet_type
        classified_rts = []
        for rt in route_tables:
            rt_type = self._route_table_type(
                rt, igws
            )
            classified_rts.append(
                {
                    "route_table_id": rt[
                        "route_table_id"
                    ],
                    "subnet_type": rt_type,
                    "routes": rt["routes"],
                }
            )

        vpcs = self._get_vpcs(
            ec2,
            flow_log_vpc_ids=flow_log_vpc_ids,
            igw_vpc_ids=igw_vpc_ids,
            nat_vpc_ids=nat_vpc_ids,
            vpc_azs=vpc_azs,
            vpc_has_private=vpc_has_private,
        )

        return "vpc", {
            "vpcs": vpcs,
            "flow_logs": flow_logs,
            "nacls": self._get_nacls(ec2),
            "subnets": classified_subnets,
            "security_groups": (
                self._get_security_groups(ec2)
            ),
            "route_tables": classified_rts,
            "peering_connections": (
                self._get_peering_connections(ec2)
            ),
            "transit_gateways": (
                self._get_transit_gateways(ec2)
            ),
            "internet_gateways": igws,
            "nat_gateways": nat_gws,
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        ec2 = self.session.client("ec2")
        if resource_id.startswith("vpc-"):
            vpcs = self._get_vpcs(
                ec2, vpc_ids=[resource_id]
            )
            return vpcs[0] if vpcs else {}
        return {}

    # --------------------------------------------------
    # VPCs (enriched)
    # --------------------------------------------------

    def _get_vpcs(
        self,
        ec2,
        vpc_ids: list | None = None,
        flow_log_vpc_ids: set | None = None,
        igw_vpc_ids: set | None = None,
        nat_vpc_ids: set | None = None,
        vpc_azs: dict | None = None,
        vpc_has_private: dict | None = None,
    ) -> list[dict]:
        vpcs = []
        flow_log_vpc_ids = flow_log_vpc_ids or set()
        igw_vpc_ids = igw_vpc_ids or set()
        nat_vpc_ids = nat_vpc_ids or set()
        vpc_azs = vpc_azs or {}
        vpc_has_private = vpc_has_private or {}

        try:
            kwargs = {}
            if vpc_ids:
                kwargs["VpcIds"] = vpc_ids
            resp = ec2.describe_vpcs(**kwargs)
            for v in resp["Vpcs"]:
                vid = v["VpcId"]
                tags = {
                    t["Key"]: t["Value"]
                    for t in v.get("Tags", [])
                }

                dns_support = (
                    self._get_vpc_attribute(
                        ec2,
                        vid,
                        "enableDnsSupport",
                    )
                )
                dns_hostnames = (
                    self._get_vpc_attribute(
                        ec2,
                        vid,
                        "enableDnsHostnames",
                    )
                )
                resource_count = (
                    self._count_vpc_instances(
                        ec2, vid
                    )
                )
                has_s3 = (
                    self._has_s3_endpoint(ec2, vid)
                )

                vpcs.append(
                    {
                        "vpc_id": vid,
                        "cidr_block": v.get(
                            "CidrBlock", ""
                        ),
                        "is_default": v.get(
                            "IsDefault", False
                        ),
                        "flow_logs_enabled": (
                            vid in flow_log_vpc_ids
                        ),
                        "resource_count": (
                            resource_count
                        ),
                        "enable_dns_support": (
                            dns_support
                        ),
                        "enable_dns_hostnames": (
                            dns_hostnames
                        ),
                        "availability_zone_count": (
                            len(
                                vpc_azs.get(
                                    vid, set()
                                )
                            )
                        ),
                        "tags": tags,
                        "has_s3_endpoint": has_s3,
                        "has_internet_gateway": (
                            vid in igw_vpc_ids
                        ),
                        "has_private_subnets": (
                            vpc_has_private.get(
                                vid, False
                            )
                        ),
                        "has_nat_gateway": (
                            vid in nat_vpc_ids
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_vpcs: %s", e
            )
        return vpcs

    def _get_vpc_attribute(
        self, ec2, vpc_id: str, attribute: str
    ) -> bool:
        try:
            resp = ec2.describe_vpc_attribute(
                VpcId=vpc_id,
                Attribute=attribute,
            )
            # Response key matches attribute name
            # with first letter capitalized
            key = attribute[0].upper() + attribute[1:]
            return (
                resp.get(key, {}).get("Value", False)
            )
        except Exception as e:
            logger.error(
                "VPC describe_vpc_attribute "
                "(%s, %s): %s",
                vpc_id,
                attribute,
                e,
            )
            return False

    def _count_vpc_instances(
        self, ec2, vpc_id: str
    ) -> int:
        try:
            resp = ec2.describe_instances(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    }
                ]
            )
            count = 0
            for res in resp.get(
                "Reservations", []
            ):
                count += len(
                    res.get("Instances", [])
                )
            return count
        except Exception as e:
            logger.error(
                "VPC count instances (%s): %s",
                vpc_id,
                e,
            )
            return 0

    def _has_s3_endpoint(
        self, ec2, vpc_id: str
    ) -> bool:
        try:
            resp = ec2.describe_vpc_endpoints(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    },
                    {
                        "Name": "service-name",
                        "Values": [
                            "com.amazonaws.*.s3"
                        ],
                    },
                ]
            )
            endpoints = resp.get(
                "VpcEndpoints", []
            )
            return len(endpoints) > 0
        except Exception as e:
            logger.error(
                "VPC describe_vpc_endpoints "
                "(%s): %s",
                vpc_id,
                e,
            )
            return False

    # --------------------------------------------------
    # Flow Logs
    # --------------------------------------------------

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

    # --------------------------------------------------
    # Network ACLs
    # --------------------------------------------------

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
                    pr = e.get("PortRange", {})
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
                            "port_range": {
                                "from": pr.get(
                                    "From"
                                ),
                                "to": pr.get(
                                    "To"
                                ),
                            },
                        }
                    )
                nacls.append(
                    {
                        "network_acl_id": nacl[
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

    # --------------------------------------------------
    # Subnets (raw — classified later in collect)
    # --------------------------------------------------

    def _get_subnets_raw(
        self, ec2
    ) -> list[dict]:
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
                        "subnet_id": s[
                            "SubnetId"
                        ],
                        "arn": s.get(
                            "SubnetArn", ""
                        ),
                        "vpc_id": s.get(
                            "VpcId", ""
                        ),
                        "cidr_block": s.get(
                            "CidrBlock", ""
                        ),
                        "availability_zone": (
                            s.get(
                                "AvailabilityZone",
                                "",
                            )
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

    # --------------------------------------------------
    # Security Groups
    # --------------------------------------------------

    def _get_security_groups(
        self, ec2
    ) -> list[dict]:
        sgs = []
        try:
            resp = ec2.describe_security_groups()
            for sg in resp.get(
                "SecurityGroups", []
            ):
                ip_perms = []
                for rule in sg.get(
                    "IpPermissions", []
                ):
                    ip_perms.append(
                        self._normalize_sg_rule(
                            rule
                        )
                    )

                ip_perms_egress = []
                for rule in sg.get(
                    "IpPermissionsEgress", []
                ):
                    ip_perms_egress.append(
                        self._normalize_sg_rule(
                            rule
                        )
                    )

                sgs.append(
                    {
                        "group_id": sg[
                            "GroupId"
                        ],
                        "group_name": sg.get(
                            "GroupName", ""
                        ),
                        "vpc_id": sg.get(
                            "VpcId", ""
                        ),
                        "ip_permissions": ip_perms,
                        "ip_permissions_egress": (
                            ip_perms_egress
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_security_groups: %s",
                e,
            )
        return sgs

    @staticmethod
    def _normalize_sg_rule(rule: dict) -> dict:
        ip_ranges = [
            {"cidr_ip": r.get("CidrIp", "")}
            for r in rule.get("IpRanges", [])
        ]
        return {
            "from_port": rule.get(
                "FromPort", 0
            ),
            "to_port": rule.get("ToPort", 0),
            "ip_protocol": rule.get(
                "IpProtocol", "-1"
            ),
            "ip_ranges": ip_ranges,
        }

    # --------------------------------------------------
    # Route Tables
    # --------------------------------------------------

    def _get_route_tables(
        self, ec2
    ) -> list[dict]:
        rts = []
        try:
            resp = ec2.describe_route_tables()
            for rt in resp.get(
                "RouteTables", []
            ):
                routes = []
                for r in rt.get("Routes", []):
                    gw = r.get(
                        "GatewayId",
                        r.get(
                            "NatGatewayId",
                            r.get(
                                "TransitGatewayId",
                                "",
                            ),
                        ),
                    )
                    routes.append(
                        {
                            "destination_cidr_block": (
                                r.get(
                                    "DestinationCidrBlock",
                                    "",
                                )
                            ),
                            "gateway_id": gw,
                        }
                    )

                # Track associated subnet IDs
                assoc_subnets = [
                    a.get("SubnetId", "")
                    for a in rt.get(
                        "Associations", []
                    )
                    if a.get("SubnetId")
                ]

                rts.append(
                    {
                        "route_table_id": rt[
                            "RouteTableId"
                        ],
                        "vpc_id": rt.get(
                            "VpcId", ""
                        ),
                        "routes": routes,
                        "associated_subnets": (
                            assoc_subnets
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_route_tables: %s", e
            )
        return rts

    def _build_subnet_type_map(
        self,
        route_tables: list[dict],
        igws: list[dict],
    ) -> dict[str, str]:
        """Map subnet_id -> 'public'|'private'
        based on whether the route table has an
        IGW route for 0.0.0.0/0."""
        igw_ids = {
            igw["igw_id"] for igw in igws
        }
        subnet_type: dict[str, str] = {}
        for rt in route_tables:
            has_igw = any(
                r.get("gateway_id", "") in igw_ids
                and r.get(
                    "destination_cidr_block", ""
                )
                == "0.0.0.0/0"
                for r in rt.get("routes", [])
            )
            stype = (
                "public" if has_igw else "private"
            )
            for sid in rt.get(
                "associated_subnets", []
            ):
                subnet_type[sid] = stype
        return subnet_type

    @staticmethod
    def _route_table_type(
        rt: dict, igws: list[dict]
    ) -> str:
        """Determine if a route table is public
        or private based on IGW routes."""
        igw_ids = {
            igw["igw_id"] for igw in igws
        }
        for r in rt.get("routes", []):
            gw = r.get("gateway_id", "")
            dest = r.get(
                "destination_cidr_block", ""
            )
            if gw in igw_ids and (
                dest == "0.0.0.0/0"
            ):
                return "public"
        return "private"

    # --------------------------------------------------
    # Internet Gateways
    # --------------------------------------------------

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
                    if a.get("State")
                    == "available"
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

    # --------------------------------------------------
    # NAT Gateways
    # --------------------------------------------------

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
                "VPC describe_nat_gateways: %s",
                e,
            )
        return nats

    # --------------------------------------------------
    # VPC Peering Connections
    # --------------------------------------------------

    def _get_peering_connections(
        self, ec2
    ) -> list[dict]:
        peers = []
        try:
            resp = (
                ec2.describe_vpc_peering_connections()
            )
            for p in resp.get(
                "VpcPeeringConnections", []
            ):
                req_info = p.get(
                    "RequesterVpcInfo", {}
                )
                peers.append(
                    {
                        "vpc_peering_connection_id": (
                            p["VpcPeeringConnectionId"]
                        ),
                        "status": {
                            "code": p.get(
                                "Status", {}
                            ).get("Code", ""),
                        },
                        "requester_cidr_block": (
                            req_info.get(
                                "CidrBlock", ""
                            )
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_vpc_peering"
                "_connections: %s",
                e,
            )
        return peers

    # --------------------------------------------------
    # Transit Gateways
    # --------------------------------------------------

    def _get_transit_gateways(
        self, ec2
    ) -> list[dict]:
        tgws = []
        try:
            resp = (
                ec2.describe_transit_gateways()
            )
            for tgw in resp.get(
                "TransitGateways", []
            ):
                tags = {
                    t["Key"]: t["Value"]
                    for t in tgw.get("Tags", [])
                }
                opts = tgw.get("Options", {})
                tgws.append(
                    {
                        "transit_gateway_id": tgw[
                            "TransitGatewayId"
                        ],
                        "default_route_table_propagation": (
                            opts.get(
                                "DefaultRouteTablePropagation",
                                "disable",
                            )
                        ),
                        "tags": tags,
                    }
                )
        except Exception as e:
            logger.error(
                "VPC describe_transit_gateways"
                ": %s",
                e,
            )
        return tgws
