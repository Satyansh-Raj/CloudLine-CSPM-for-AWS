package aws.compute.ec2_test

import data.aws.compute.ec2

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in ec2.violations with input as inp
	v.check_id == check_id
])

# Minimal compliant instance
_good_inst := {
	"instance_id": "i-abc123",
	"arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
	"state": {"name": "running"},
	"metadata_options": {"http_tokens": "required"},
	"public_ip_address": null,
	"vpc_id": "vpc-custom",
	"monitoring": {"state": "enabled"},
	"tags": {"environment": "production"},
	"block_device_mappings": [{
		"device_name": "/dev/xvda",
		"ebs": {"encrypted": true},
	}],
	"root_device_name": "/dev/xvda",
	"iam_instance_profile": {"attached_policies": [{"policy_name": "ReadOnly"}]},
	"disable_api_termination": true,
	"key_name": null,
	"instance_type": "t3.medium",
	"days_since_stopped": 0,
}

# Minimal compliant security group
_good_sg := {
	"group_id": "sg-abc123",
	"ip_permissions": [],
	"ip_permissions_egress": [],
	"tags": {"environment": "production", "exposure": "public"},
}

# =========================================================================
# ec2_01 — IMDSv2 required
# =========================================================================
test_ec2_01_alarm if {
	inst := object.union(_good_inst, {"metadata_options": {"http_tokens": "optional"}})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_01"
}

test_ec2_01_compliant if {
	_violations_for("ec2_01", {"ec2": {"instances": [_good_inst]}}) == 0
}

# =========================================================================
# ec2_02 — No public IP on production instances
# =========================================================================
test_ec2_02_alarm if {
	inst := object.union(_good_inst, {"public_ip_address": "54.1.2.3"})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_02"
}

test_ec2_02_compliant_no_ip if {
	_violations_for("ec2_02", {"ec2": {"instances": [_good_inst]}}) == 0
}

test_ec2_02_compliant_dev_env if {
	inst := object.union(_good_inst, {
		"public_ip_address": "54.1.2.3",
		"tags": {"environment": "development"},
	})
	_violations_for("ec2_02", {"ec2": {"instances": [inst]}}) == 0
}

# =========================================================================
# ec2_03 — No instances in default VPC
# =========================================================================
test_ec2_03_alarm if {
	inst := object.union(_good_inst, {"vpc_id": "vpc-default"})
	r := ec2.violations with input as {"ec2": {
		"instances": [inst],
		"default_vpc_id": "vpc-default",
	}}
	some v in r
	v.check_id == "ec2_03"
}

test_ec2_03_compliant if {
	_violations_for("ec2_03", {"ec2": {
		"instances": [_good_inst],
		"default_vpc_id": "vpc-default",
	}}) == 0
}

# =========================================================================
# ec2_04 — Detailed monitoring enabled
# =========================================================================
test_ec2_04_alarm if {
	inst := object.union(_good_inst, {"monitoring": {"state": "disabled"}})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_04"
}

test_ec2_04_compliant if {
	_violations_for("ec2_04", {"ec2": {"instances": [_good_inst]}}) == 0
}

test_ec2_04_stopped_ok if {
	inst := object.union(_good_inst, {
		"monitoring": {"state": "disabled"},
		"state": {"name": "stopped"},
		"days_since_stopped": 5,
	})
	_violations_for("ec2_04", {"ec2": {"instances": [inst]}}) == 0
}

# =========================================================================
# ec2_05 — No SSH from 0.0.0.0/0
# =========================================================================
test_ec2_05_alarm if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"from_port": 22,
		"to_port": 22,
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
	}]})
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_05"
}

test_ec2_05_compliant if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"from_port": 22,
		"to_port": 22,
		"ip_ranges": [{"cidr_ip": "10.0.0.0/8"}],
	}]})
	_violations_for("ec2_05", {"ec2": {"security_groups": [sg]}}) == 0
}

test_ec2_05_alarm_port_range if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"from_port": 0,
		"to_port": 65535,
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
	}]})
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_05"
}

# =========================================================================
# ec2_06 — No RDP from 0.0.0.0/0
# =========================================================================
test_ec2_06_alarm if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"from_port": 3389,
		"to_port": 3389,
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
	}]})
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_06"
}

test_ec2_06_compliant if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"from_port": 3389,
		"to_port": 3389,
		"ip_ranges": [{"cidr_ip": "10.0.0.0/8"}],
	}]})
	_violations_for("ec2_06", {"ec2": {"security_groups": [sg]}}) == 0
}

# =========================================================================
# ec2_07 — No all-traffic inbound from 0.0.0.0/0
# =========================================================================
test_ec2_07_alarm if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"ip_protocol": "-1",
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
	}]})
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_07"
}

test_ec2_07_compliant if {
	_violations_for("ec2_07", {"ec2": {"security_groups": [_good_sg]}}) == 0
}

# =========================================================================
# ec2_08 — Root EBS volume encrypted
# =========================================================================
test_ec2_08_alarm if {
	inst := object.union(_good_inst, {"block_device_mappings": [{
		"device_name": "/dev/xvda",
		"ebs": {"encrypted": false},
	}]})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_08"
}

test_ec2_08_compliant if {
	_violations_for("ec2_08", {"ec2": {"instances": [_good_inst]}}) == 0
}

# =========================================================================
# ec2_09 — No instance IAM role with AdministratorAccess
# =========================================================================
test_ec2_09_alarm if {
	inst := object.union(_good_inst, {"iam_instance_profile": {"attached_policies": [{"policy_name": "AdministratorAccess"}]}})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_09"
}

test_ec2_09_compliant if {
	_violations_for("ec2_09", {"ec2": {"instances": [_good_inst]}}) == 0
}

# =========================================================================
# ec2_10 — EBS snapshots not public
# =========================================================================
test_ec2_10_alarm if {
	r := ec2.violations with input as {"ec2": {"snapshots": [{
		"snapshot_id": "snap-abc",
		"create_volume_permissions": [{"group": "all"}],
	}]}}
	some v in r
	v.check_id == "ec2_10"
}

test_ec2_10_compliant if {
	_violations_for("ec2_10", {"ec2": {"snapshots": [{
		"snapshot_id": "snap-abc",
		"create_volume_permissions": [],
	}]}}) == 0
}

# =========================================================================
# ec2_11 — Termination protection on production
# =========================================================================
test_ec2_11_alarm if {
	inst := object.union(_good_inst, {"disable_api_termination": false})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_11"
}

test_ec2_11_compliant if {
	_violations_for("ec2_11", {"ec2": {"instances": [_good_inst]}}) == 0
}

test_ec2_11_dev_no_alarm if {
	inst := object.union(_good_inst, {
		"disable_api_termination": false,
		"tags": {"environment": "development"},
	})
	_violations_for("ec2_11", {"ec2": {"instances": [inst]}}) == 0
}

# =========================================================================
# ec2_12 — Stopped > 90 days
# =========================================================================
test_ec2_12_alarm if {
	inst := object.union(_good_inst, {
		"state": {"name": "stopped"},
		"days_since_stopped": 120,
	})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_12"
}

test_ec2_12_compliant if {
	inst := object.union(_good_inst, {
		"state": {"name": "stopped"},
		"days_since_stopped": 30,
	})
	_violations_for("ec2_12", {"ec2": {"instances": [inst]}}) == 0
}

test_ec2_12_running_ok if {
	_violations_for("ec2_12", {"ec2": {"instances": [_good_inst]}}) == 0
}

# =========================================================================
# ec2_13 — No all-traffic inbound from ::/0 (IPv6)
# =========================================================================
test_ec2_13_alarm if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"ip_protocol": "-1",
		"ip_ranges": [],
		"ipv6_ranges": [{"cidr_ipv6": "::/0"}],
	}]})
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_13"
}

test_ec2_13_compliant if {
	_violations_for("ec2_13", {"ec2": {"security_groups": [_good_sg]}}) == 0
}

# =========================================================================
# ec2_14 — Running instance must have IAM instance profile
# =========================================================================
test_ec2_14_alarm if {
	inst := object.remove(_good_inst, ["iam_instance_profile"])
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_14"
}

test_ec2_14_compliant if {
	_violations_for("ec2_14", {"ec2": {"instances": [_good_inst]}}) == 0
}

# =========================================================================
# ec2_15 — Internal SG no HTTPS from 0.0.0.0/0
# =========================================================================
test_ec2_15_alarm if {
	sg := {
		"group_id": "sg-internal",
		"tags": {"exposure": "internal", "environment": "production"},
		"ip_permissions": [{
			"from_port": 443,
			"to_port": 443,
			"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
		}],
		"ip_permissions_egress": [],
	}
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_15"
}

test_ec2_15_compliant_public_sg if {
	sg := object.union(_good_sg, {"ip_permissions": [{
		"from_port": 443,
		"to_port": 443,
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
	}]})
	_violations_for("ec2_15", {"ec2": {"security_groups": [sg]}}) == 0
}

# =========================================================================
# ec2_16 — Production SG no unrestricted egress
# =========================================================================
test_ec2_16_alarm if {
	sg := object.union(_good_sg, {"ip_permissions_egress": [{
		"ip_protocol": "-1",
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
	}]})
	r := ec2.violations with input as {"ec2": {"security_groups": [sg]}}
	some v in r
	v.check_id == "ec2_16"
}

test_ec2_16_compliant_restricted if {
	_violations_for("ec2_16", {"ec2": {"security_groups": [_good_sg]}}) == 0
}

test_ec2_16_dev_ok if {
	sg := object.union(_good_sg, {
		"tags": {"environment": "development"},
		"ip_permissions_egress": [{
			"ip_protocol": "-1",
			"ip_ranges": [{"cidr_ip": "0.0.0.0/0"}],
		}],
	})
	_violations_for("ec2_16", {"ec2": {"security_groups": [sg]}}) == 0
}

# =========================================================================
# ec2_17 — Production instances must not use key pairs
# =========================================================================
test_ec2_17_alarm if {
	inst := object.union(_good_inst, {"key_name": "my-keypair"})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_17"
}

test_ec2_17_compliant_no_key if {
	_violations_for("ec2_17", {"ec2": {"instances": [_good_inst]}}) == 0
}

test_ec2_17_dev_ok if {
	inst := object.union(_good_inst, {
		"key_name": "my-keypair",
		"tags": {"environment": "development"},
	})
	_violations_for("ec2_17", {"ec2": {"instances": [inst]}}) == 0
}

# =========================================================================
# ec2_18 — No deprecated instance types (t1.*)
# =========================================================================
test_ec2_18_alarm if {
	inst := object.union(_good_inst, {"instance_type": "t1.micro"})
	r := ec2.violations with input as {"ec2": {"instances": [inst]}}
	some v in r
	v.check_id == "ec2_18"
}

test_ec2_18_compliant if {
	_violations_for("ec2_18", {"ec2": {"instances": [_good_inst]}}) == 0
}

# =========================================================================
# ec2_19 — No unused elastic IPs
# =========================================================================
test_ec2_19_alarm if {
	r := ec2.violations with input as {"ec2": {"elastic_ips": [{
		"public_ip": "54.1.2.3",
		"allocation_id": "eipalloc-abc",
		"instance_id": null,
		"network_interface_id": null,
	}]}}
	some v in r
	v.check_id == "ec2_19"
}

test_ec2_19_compliant if {
	_violations_for("ec2_19", {"ec2": {"elastic_ips": [{
		"public_ip": "54.1.2.3",
		"allocation_id": "eipalloc-abc",
		"instance_id": "i-abc",
		"network_interface_id": "eni-abc",
	}]}}) == 0
}

# =========================================================================
# ec2_20 — Account-owned AMIs must not be public
# =========================================================================
test_ec2_20_alarm if {
	r := ec2.violations with input as {
		"account_id": "123456789012",
		"ec2": {"amis": [{
			"image_id": "ami-abc123",
			"public": true,
			"owner_id": "123456789012",
		}]},
	}
	some v in r
	v.check_id == "ec2_20"
}

test_ec2_20_compliant_private if {
	_violations_for("ec2_20", {
		"account_id": "123456789012",
		"ec2": {"amis": [{
			"image_id": "ami-abc123",
			"public": false,
			"owner_id": "123456789012",
		}]},
	}) == 0
}

test_ec2_20_compliant_other_owner if {
	_violations_for("ec2_20", {
		"account_id": "123456789012",
		"ec2": {"amis": [{
			"image_id": "ami-abc123",
			"public": true,
			"owner_id": "999999999999",
		}]},
	}) == 0
}

# =========================================================================
# ec2_00 — Error handler
# =========================================================================
test_ec2_00_error if {
	r := ec2.error with input as {"account_id": "123456789012"}
	some v in r
	v.check_id == "ec2_00"
}

test_ec2_00_no_error if {
	r := ec2.error with input as {"ec2": {"instances": []}}
	count(r) == 0
}
