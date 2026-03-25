package aws.network.vpc

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule vpc_flow_logs — VPC Flow Logs must be enabled for all VPCs
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	not vpc.flow_logs_enabled
	result := {
		"check_id": "vpc_flow_logs",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"VPC '%s' does not have Flow Logs enabled",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_01",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_default_no_resources — Default VPC must not have any resources attached
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	vpc.is_default == true
	vpc.resource_count > 0
	result := {
		"check_id": "vpc_default_no_resources",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Default VPC '%s' has %d resources — workloads should use custom VPCs",
			[vpc.vpc_id, vpc.resource_count],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_02",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_default_sg_no_inbound — Default security group must block all inbound traffic
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.vpc.security_groups
	sg.group_name == "default"
	count(sg.ip_permissions) > 0
	result := {
		"check_id": "vpc_default_sg_no_inbound",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Default security group '%s' in VPC '%s' allows inbound traffic",
			[sg.group_id, sg.vpc_id],
		),
		"resource": sg.group_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_03",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_default_sg_no_outbound — Default security group must block all outbound traffic
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.vpc.security_groups
	sg.group_name == "default"
	some rule in sg.ip_permissions_egress
	rule.ip_protocol == "-1"
	result := {
		"check_id": "vpc_default_sg_no_outbound",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Default security group '%s' allows unrestricted outbound traffic",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_04",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_nacl_no_all_inbound — NACLs must not allow all inbound traffic from 0.0.0.0/0
# ---------------------------------------------------------------------------
violations contains result if {
	some nacl in input.vpc.nacls
	some entry in nacl.entries
	entry.rule_action == "allow"
	entry.egress == false
	entry.protocol == "-1"
	entry.cidr_block == "0.0.0.0/0"
	result := {
		"check_id": "vpc_nacl_no_all_inbound",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"NACL '%s' allows all inbound traffic from 0.0.0.0/0",
			[nacl.network_acl_id],
		),
		"resource": nacl.network_acl_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_05",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_dns_resolution — DNS resolution must be enabled in all VPCs
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	vpc.enable_dns_support == false
	result := {
		"check_id": "vpc_dns_resolution",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"VPC '%s' has DNS resolution disabled",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_06",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_dns_hostnames — DNS hostnames must be enabled for all VPCs
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	vpc.enable_dns_hostnames == false
	result := {
		"check_id": "vpc_dns_hostnames",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"VPC '%s' has DNS hostnames disabled",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_06",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_private_no_public_ip — Private subnets must not auto-assign public IPs
# ---------------------------------------------------------------------------
violations contains result if {
	some subnet in input.vpc.subnets
	subnet.subnet_type == "private"
	subnet.map_public_ip_on_launch == true
	result := {
		"check_id": "vpc_private_no_public_ip",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Private subnet '%s' auto-assigns public IPs",
			[subnet.subnet_id],
		),
		"resource": subnet.subnet_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_08",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_private_no_igw_route — Private subnets must not route directly to Internet Gateway
# ---------------------------------------------------------------------------
violations contains result if {
	some rt in input.vpc.route_tables
	rt.subnet_type == "private"
	some route in rt.routes
	route.destination_cidr_block == "0.0.0.0/0"
	startswith(route.gateway_id, "igw-")
	result := {
		"check_id": "vpc_private_no_igw_route",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Private route table '%s' routes 0.0.0.0/0 to Internet Gateway",
			[rt.route_table_id],
		),
		"resource": rt.route_table_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_09",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_multi_az — VPC must have at least 2 availability zones for HA
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	vpc.availability_zone_count < 2
	vpc.tags.environment == "production"
	result := {
		"check_id": "vpc_multi_az",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production VPC '%s' spans only %d AZ (minimum 2 required)",
			[vpc.vpc_id, vpc.availability_zone_count],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_10",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_sg_no_all_ports — Security groups must not allow all inbound ports from 0.0.0.0/0
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.vpc.security_groups
	some rule in sg.ip_permissions
	rule.from_port == 0
	rule.to_port == 65535
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	result := {
		"check_id": "vpc_sg_no_all_ports",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security group '%s' allows all ports (0-65535) from 0.0.0.0/0",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_11",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_peering_internal_cidr — VPC peering connections must restrict CIDR to internal ranges
# ---------------------------------------------------------------------------
violations contains result if {
	some peering in input.vpc.peering_connections
	peering.status.code == "active"
	peering.requester_cidr_block == "0.0.0.0/0"
	result := {
		"check_id": "vpc_peering_internal_cidr",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"VPC peering connection '%s' uses unrestricted CIDR 0.0.0.0/0",
			[peering.vpc_peering_connection_id],
		),
		"resource": peering.vpc_peering_connection_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_12",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_endpoints_s3_dynamodb — VPC endpoints must be used for S3 and DynamoDB access
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	not vpc.has_s3_endpoint
	vpc.tags.environment == "production"
	result := {
		"check_id": "vpc_endpoints_s3_dynamodb",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production VPC '%s' has no S3 VPC endpoint — traffic routes via internet",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_13",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_cidr_not_slash8 — VPC CIDR must not be /8 (overly broad)
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	endswith(vpc.cidr_block, "/8")
	result := {
		"check_id": "vpc_cidr_not_slash8",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"VPC '%s' has an overly broad CIDR block '%s' (/8)",
			[vpc.vpc_id, vpc.cidr_block],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_14",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_nacl_no_admin_ports — NACLs must not allow unrestricted inbound on admin ports
# ---------------------------------------------------------------------------
admin_ports := {22, 3389, 5432, 3306, 1433, 6379, 27017}

violations contains result if {
	some nacl in input.vpc.nacls
	some entry in nacl.entries
	some port in admin_ports
	entry.rule_action == "allow"
	entry.egress == false
	entry.port_range.from <= port
	entry.port_range.to >= port
	entry.cidr_block == "0.0.0.0/0"
	result := {
		"check_id": "vpc_nacl_no_admin_ports",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"NACL '%s' allows inbound on admin port %d from 0.0.0.0/0",
			[nacl.network_acl_id, port],
		),
		"resource": nacl.network_acl_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_15",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_tgw_restrict_propagation — Transit Gateway must not allow unrestricted route propagation
# ---------------------------------------------------------------------------
violations contains result if {
	some tgw in input.vpc.transit_gateways
	tgw.default_route_table_propagation == "enable"
	tgw.tags.environment == "production"
	result := {
		"check_id": "vpc_tgw_restrict_propagation",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Transit Gateway '%s' has default route table propagation enabled",
			[tgw.transit_gateway_id],
		),
		"resource": tgw.transit_gateway_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_16",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_private_nat_gateway — VPC must use private NAT Gateway for outbound (not IGW directly)
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	vpc.tags.environment == "production"
	vpc.has_private_subnets == true
	vpc.has_nat_gateway == false
	result := {
		"check_id": "vpc_private_nat_gateway",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production VPC '%s' has private subnets but no NAT Gateway",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_17",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_sg_no_db_ports_open — Security groups must not use 0.0.0.0/0 for database ports
# ---------------------------------------------------------------------------
db_ports := {3306, 5432, 1433, 27017, 6379, 9200}

violations contains result if {
	some sg in input.vpc.security_groups
	some rule in sg.ip_permissions
	some port in db_ports
	rule.from_port <= port
	rule.to_port >= port
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	result := {
		"check_id": "vpc_sg_no_db_ports_open",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security group '%s' allows access to database port %d from 0.0.0.0/0",
			[sg.group_id, port],
		),
		"resource": sg.group_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_18",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_no_igw_sensitive — Internet Gateway must not be attached to sensitive VPCs
# ---------------------------------------------------------------------------
violations contains result if {
	some vpc in input.vpc.vpcs
	vpc.tags.data_classification == "restricted"
	vpc.has_internet_gateway == true
	result := {
		"check_id": "vpc_no_igw_sensitive",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Restricted VPC '%s' has an Internet Gateway attached",
			[vpc.vpc_id],
		),
		"resource": vpc.vpc_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_19",
	}
}

# ---------------------------------------------------------------------------
# Rule vpc_flow_logs_reject — Flow Logs must capture REJECT traffic (not ACCEPT-only)
# ---------------------------------------------------------------------------
violations contains result if {
	some log in input.vpc.flow_logs
	log.traffic_type == "ACCEPT"
	result := {
		"check_id": "vpc_flow_logs_reject",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"VPC Flow Log '%s' only captures ACCEPT traffic — REJECT also required",
			[log.flow_log_id],
		),
		"resource": log.flow_log_id,
		"domain": "network",
		"service": "vpc",
		"remediation_id": "REM_vpc_01",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.vpc
	result := {
		"check_id": "vpc_error",
		"status": "error",
		"severity": "critical",
		"reason": "VPC data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
		"service": "vpc",
	}
}
