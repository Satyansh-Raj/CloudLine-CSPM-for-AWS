package aws.network.vpc_test

import data.aws.network.vpc

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in vpc.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# Minimal compliant fixtures
# =========================================================================
_good_vpc := {
	"vpc_id": "vpc-abc123",
	"is_default": false,
	"resource_count": 0,
	"flow_logs_enabled": true,
	"enable_dns_support": true,
	"enable_dns_hostnames": true,
	"availability_zone_count": 3,
	"cidr_block": "10.0.0.0/16",
	"has_s3_endpoint": true,
	"has_private_subnets": true,
	"has_nat_gateway": true,
	"has_internet_gateway": false,
	"tags": {
		"environment": "production",
		"data_classification": "internal",
	},
}

_good_sg := {
	"group_id": "sg-abc123",
	"group_name": "my-app-sg",
	"vpc_id": "vpc-abc123",
	"ip_permissions": [],
	"ip_permissions_egress": [],
}

_good_nacl := {
	"network_acl_id": "acl-abc123",
	"entries": [{
		"rule_action": "allow",
		"egress": false,
		"protocol": "6",
		"cidr_block": "10.0.0.0/16",
		"port_range": {"from": 443, "to": 443},
	}],
}

_good_subnet := {
	"subnet_id": "subnet-abc123",
	"subnet_type": "private",
	"map_public_ip_on_launch": false,
}

_good_rt := {
	"route_table_id": "rtb-abc123",
	"subnet_type": "private",
	"routes": [{
		"destination_cidr_block": "0.0.0.0/0",
		"gateway_id": "nat-abc123",
	}],
}

_good_peering := {
	"vpc_peering_connection_id": "pcx-abc123",
	"status": {"code": "active"},
	"requester_cidr_block": "10.0.0.0/16",
}

_good_tgw := {
	"transit_gateway_id": "tgw-abc123",
	"default_route_table_propagation": "disable",
	"tags": {"environment": "production"},
}

_good_flow_log := {
	"flow_log_id": "fl-abc123",
	"traffic_type": "ALL",
}

_full_input := {
	"vpc": {
		"vpcs": [_good_vpc],
		"security_groups": [_good_sg],
		"nacls": [_good_nacl],
		"subnets": [_good_subnet],
		"route_tables": [_good_rt],
		"peering_connections": [_good_peering],
		"transit_gateways": [_good_tgw],
		"flow_logs": [_good_flow_log],
	},
}

# =========================================================================
# vpc_01 — Flow Logs not enabled
# =========================================================================
test_vpc_01_alarm if {
	v := object.remove(_good_vpc, ["flow_logs_enabled"])
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_01"
}

test_vpc_01_compliant if {
	_violations_for("vpc_01", _full_input) == 0
}

# =========================================================================
# vpc_02 — Default VPC with resources
# =========================================================================
test_vpc_02_alarm if {
	v := object.union(_good_vpc, {
		"is_default": true,
		"resource_count": 5,
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_02"
}

test_vpc_02_compliant if {
	_violations_for("vpc_02", _full_input) == 0
}

test_vpc_02_compliant_default_empty if {
	v := object.union(_good_vpc, {
		"is_default": true,
		"resource_count": 0,
	})
	_violations_for("vpc_02", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)) == 0
}

# =========================================================================
# vpc_03 — Default SG allows inbound
# =========================================================================
test_vpc_03_alarm if {
	sg := object.union(_good_sg, {
		"group_name": "default",
		"ip_permissions": [{"from_port": 0, "to_port": 65535}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"security_groups": [sg]})},
	)
	some x in r
	x.check_id == "vpc_03"
}

test_vpc_03_compliant if {
	_violations_for("vpc_03", _full_input) == 0
}

test_vpc_03_compliant_non_default if {
	sg := object.union(_good_sg, {
		"group_name": "my-sg",
		"ip_permissions": [{"from_port": 443, "to_port": 443}],
	})
	_violations_for("vpc_03", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"security_groups": [sg]})},
	)) == 0
}

# =========================================================================
# vpc_04 — Default SG unrestricted outbound
# =========================================================================
test_vpc_04_alarm if {
	sg := object.union(_good_sg, {
		"group_name": "default",
		"ip_permissions_egress": [{"ip_protocol": "-1"}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"security_groups": [sg]})},
	)
	some x in r
	x.check_id == "vpc_04"
}

test_vpc_04_compliant if {
	_violations_for("vpc_04", _full_input) == 0
}

# =========================================================================
# vpc_05 — NACL allows all inbound from 0.0.0.0/0
# =========================================================================
test_vpc_05_alarm if {
	nacl := object.union(_good_nacl, {
		"entries": [{
			"rule_action": "allow",
			"egress": false,
			"protocol": "-1",
			"cidr_block": "0.0.0.0/0",
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"nacls": [nacl]})},
	)
	some x in r
	x.check_id == "vpc_05"
}

test_vpc_05_compliant if {
	_violations_for("vpc_05", _full_input) == 0
}

# =========================================================================
# vpc_06 — DNS support disabled
# =========================================================================
test_vpc_06_alarm if {
	v := object.union(_good_vpc, {"enable_dns_support": false})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_06"
}

test_vpc_06_compliant if {
	_violations_for("vpc_06", _full_input) == 0
}

# =========================================================================
# vpc_07 — DNS hostnames disabled
# =========================================================================
test_vpc_07_alarm if {
	v := object.union(_good_vpc, {"enable_dns_hostnames": false})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_07"
}

test_vpc_07_compliant if {
	_violations_for("vpc_07", _full_input) == 0
}

# =========================================================================
# vpc_08 — Private subnet auto-assigns public IP
# =========================================================================
test_vpc_08_alarm if {
	subnet := object.union(_good_subnet, {
		"map_public_ip_on_launch": true,
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"subnets": [subnet]})},
	)
	some x in r
	x.check_id == "vpc_08"
}

test_vpc_08_compliant if {
	_violations_for("vpc_08", _full_input) == 0
}

test_vpc_08_compliant_public_subnet if {
	subnet := object.union(_good_subnet, {
		"subnet_type": "public",
		"map_public_ip_on_launch": true,
	})
	_violations_for("vpc_08", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"subnets": [subnet]})},
	)) == 0
}

# =========================================================================
# vpc_09 — Private route table routes to IGW
# =========================================================================
test_vpc_09_alarm if {
	rt := object.union(_good_rt, {
		"routes": [{
			"destination_cidr_block": "0.0.0.0/0",
			"gateway_id": "igw-abc123",
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"route_tables": [rt]})},
	)
	some x in r
	x.check_id == "vpc_09"
}

test_vpc_09_compliant if {
	_violations_for("vpc_09", _full_input) == 0
}

test_vpc_09_compliant_public_rt if {
	rt := object.union(_good_rt, {
		"subnet_type": "public",
		"routes": [{
			"destination_cidr_block": "0.0.0.0/0",
			"gateway_id": "igw-abc123",
		}],
	})
	_violations_for("vpc_09", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"route_tables": [rt]})},
	)) == 0
}

# =========================================================================
# vpc_10 — Production VPC < 2 AZs
# =========================================================================
test_vpc_10_alarm if {
	v := object.union(_good_vpc, {"availability_zone_count": 1})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_10"
}

test_vpc_10_compliant if {
	_violations_for("vpc_10", _full_input) == 0
}

test_vpc_10_compliant_dev if {
	v := object.union(
		object.remove(_good_vpc, ["tags"]),
		{
			"availability_zone_count": 1,
			"tags": {"environment": "development", "data_classification": "internal"},
		},
	)
	_violations_for("vpc_10", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)) == 0
}

# =========================================================================
# vpc_11 — SG allows all ports from 0.0.0.0/0
# =========================================================================
test_vpc_11_alarm if {
	sg := object.union(_good_sg, {
		"ip_permissions": [{
			"from_port": 0,
			"to_port": 65535,
			"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"security_groups": [sg]})},
	)
	some x in r
	x.check_id == "vpc_11"
}

test_vpc_11_compliant if {
	_violations_for("vpc_11", _full_input) == 0
}

# =========================================================================
# vpc_12 — Peering with 0.0.0.0/0 CIDR
# =========================================================================
test_vpc_12_alarm if {
	p := object.union(_good_peering, {
		"requester_cidr_block": "0.0.0.0/0",
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"peering_connections": [p]})},
	)
	some x in r
	x.check_id == "vpc_12"
}

test_vpc_12_compliant if {
	_violations_for("vpc_12", _full_input) == 0
}

# =========================================================================
# vpc_13 — No S3 VPC endpoint in production
# =========================================================================
test_vpc_13_alarm if {
	v := object.remove(_good_vpc, ["has_s3_endpoint"])
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_13"
}

test_vpc_13_compliant if {
	_violations_for("vpc_13", _full_input) == 0
}

test_vpc_13_compliant_dev if {
	v := object.union(
		object.remove(_good_vpc, ["has_s3_endpoint", "tags"]),
		{"tags": {"environment": "development", "data_classification": "internal"}},
	)
	_violations_for("vpc_13", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)) == 0
}

# =========================================================================
# vpc_14 — Overly broad /8 CIDR
# =========================================================================
test_vpc_14_alarm if {
	v := object.union(_good_vpc, {"cidr_block": "10.0.0.0/8"})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_14"
}

test_vpc_14_compliant if {
	_violations_for("vpc_14", _full_input) == 0
}

# =========================================================================
# vpc_15 — NACL allows admin port from 0.0.0.0/0
# =========================================================================
test_vpc_15_alarm_ssh if {
	nacl := object.union(_good_nacl, {
		"entries": [{
			"rule_action": "allow",
			"egress": false,
			"protocol": "6",
			"cidr_block": "0.0.0.0/0",
			"port_range": {"from": 22, "to": 22},
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"nacls": [nacl]})},
	)
	some x in r
	x.check_id == "vpc_15"
}

test_vpc_15_alarm_rdp if {
	nacl := object.union(_good_nacl, {
		"entries": [{
			"rule_action": "allow",
			"egress": false,
			"protocol": "6",
			"cidr_block": "0.0.0.0/0",
			"port_range": {"from": 3389, "to": 3389},
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"nacls": [nacl]})},
	)
	some x in r
	x.check_id == "vpc_15"
}

test_vpc_15_compliant if {
	_violations_for("vpc_15", _full_input) == 0
}

# =========================================================================
# vpc_16 — Transit Gateway default propagation
# =========================================================================
test_vpc_16_alarm if {
	tgw := object.union(_good_tgw, {
		"default_route_table_propagation": "enable",
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"transit_gateways": [tgw]})},
	)
	some x in r
	x.check_id == "vpc_16"
}

test_vpc_16_compliant if {
	_violations_for("vpc_16", _full_input) == 0
}

# =========================================================================
# vpc_17 — Production VPC no NAT Gateway
# =========================================================================
test_vpc_17_alarm if {
	v := object.union(_good_vpc, {"has_nat_gateway": false})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_17"
}

test_vpc_17_compliant if {
	_violations_for("vpc_17", _full_input) == 0
}

# =========================================================================
# vpc_18 — SG allows DB port from 0.0.0.0/0
# =========================================================================
test_vpc_18_alarm_mysql if {
	sg := object.union(_good_sg, {
		"ip_permissions": [{
			"from_port": 3306,
			"to_port": 3306,
			"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"security_groups": [sg]})},
	)
	some x in r
	x.check_id == "vpc_18"
}

test_vpc_18_alarm_postgres if {
	sg := object.union(_good_sg, {
		"ip_permissions": [{
			"from_port": 5432,
			"to_port": 5432,
			"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
		}],
	})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"security_groups": [sg]})},
	)
	some x in r
	x.check_id == "vpc_18"
}

test_vpc_18_compliant if {
	_violations_for("vpc_18", _full_input) == 0
}

# =========================================================================
# vpc_19 — IGW on restricted VPC
# =========================================================================
test_vpc_19_alarm if {
	v := object.union(
		object.remove(_good_vpc, ["tags"]),
		{
			"has_internet_gateway": true,
			"tags": {"environment": "production", "data_classification": "restricted"},
		},
	)
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)
	some x in r
	x.check_id == "vpc_19"
}

test_vpc_19_compliant if {
	_violations_for("vpc_19", _full_input) == 0
}

test_vpc_19_compliant_internal if {
	v := object.union(_good_vpc, {"has_internet_gateway": true})
	_violations_for("vpc_19", object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"vpcs": [v]})},
	)) == 0
}

# =========================================================================
# vpc_20 — Flow Log ACCEPT only
# =========================================================================
test_vpc_20_alarm if {
	fl := object.union(_good_flow_log, {"traffic_type": "ACCEPT"})
	r := vpc.violations with input as object.union(
		_full_input,
		{"vpc": object.union(_full_input.vpc, {"flow_logs": [fl]})},
	)
	some x in r
	x.check_id == "vpc_20"
}

test_vpc_20_compliant if {
	_violations_for("vpc_20", _full_input) == 0
}

# =========================================================================
# Error handler
# =========================================================================
test_error_vpc_missing if {
	r := vpc.error with input as {}
	some e in r
	e.check_id == "vpc_00"
}
