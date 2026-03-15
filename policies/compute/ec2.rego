package aws.compute.ec2

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule ec2_01 — IMDSv2 must be enforced on all instances
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.metadata_options.http_tokens != "required"
	result := {
		"check_id": "ec2_01",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EC2 instance '%s' does not enforce IMDSv2 (http_tokens != required)",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.6"],
			"nist_800_53": ["CM-6"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_ec2_01",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_02 — Instances must not have a public IP in production subnets
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.public_ip_address != null
	inst.tags.environment == "production"
	result := {
		"check_id": "ec2_02",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production EC2 instance '%s' has public IP '%s'",
			[inst.instance_id, inst.public_ip_address],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.1"],
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_ec2_02",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_03 — No instances running in the default VPC
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.vpc_id == input.ec2.default_vpc_id
	inst.state.name == "running"
	result := {
		"check_id": "ec2_03",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"EC2 instance '%s' is running in the default VPC",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.3"],
			"nist_800_53": ["SC-7"],
		},
		"remediation_id": "REM_ec2_03",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_04 — Detailed monitoring must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.monitoring.state != "enabled"
	inst.state.name == "running"
	result := {
		"check_id": "ec2_04",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' does not have detailed monitoring enabled",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.7"],
		},
		"remediation_id": "REM_ec2_04",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_05 — No security group allows unrestricted inbound SSH (port 22)
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ip_permissions
	rule.from_port <= 22
	rule.to_port >= 22
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	result := {
		"check_id": "ec2_05",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security group '%s' allows SSH (22) from 0.0.0.0/0",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.2"],
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_ec2_05",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_06 — No security group allows unrestricted inbound RDP (port 3389)
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ip_permissions
	rule.from_port <= 3389
	rule.to_port >= 3389
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	result := {
		"check_id": "ec2_06",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security group '%s' allows RDP (3389) from 0.0.0.0/0",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.2"],
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_ec2_06",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_07 — No security group allows all inbound traffic (protocol -1)
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ip_permissions
	rule.ip_protocol == "-1"
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	result := {
		"check_id": "ec2_07",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security group '%s' allows all inbound traffic from 0.0.0.0/0",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.2"],
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_ec2_07",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_08 — EBS root volumes must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	some vol in inst.block_device_mappings
	vol.device_name == inst.root_device_name
	vol.ebs.encrypted == false
	result := {
		"check_id": "ec2_08",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EC2 instance '%s' root EBS volume is not encrypted",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["2.2.1"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_ec2_08",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_09 — EC2 instances must not have an IAM role with admin access
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	some policy in inst.iam_instance_profile.attached_policies
	policy.policy_name == "AdministratorAccess"
	result := {
		"check_id": "ec2_09",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"EC2 instance '%s' has IAM role with AdministratorAccess",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["1.16"],
			"nist_800_53": ["AC-6(5)"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_ec2_09",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_10 — EBS snapshots must not be publicly shared
# ---------------------------------------------------------------------------
violations contains result if {
	some snap in input.ec2.snapshots
	some perm in snap.create_volume_permissions
	perm.group == "all"
	result := {
		"check_id": "ec2_10",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"EBS snapshot '%s' is publicly accessible",
			[snap.snapshot_id],
		),
		"resource": snap.snapshot_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["2.2.2"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_ec2_10",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_11 — Termination protection must be enabled for production instances
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.tags.environment == "production"
	inst.disable_api_termination == false
	result := {
		"check_id": "ec2_11",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production EC2 instance '%s' has termination protection disabled",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_ec2_11",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_12 — Stopped instances older than 90 days should be cleaned up
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.state.name == "stopped"
	inst.days_since_stopped > 90
	result := {
		"check_id": "ec2_12",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' has been stopped for %d days",
			[inst.instance_id, inst.days_since_stopped],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_ec2_12",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_13 — Security groups must not allow inbound on all ports from IPv6
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ip_permissions
	rule.ip_protocol == "-1"
	some cidr in rule.ipv6_ranges
	cidr.cidr_ipv6 == "::/0"
	result := {
		"check_id": "ec2_13",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security group '%s' allows all inbound traffic from ::/0 (IPv6)",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.2"],
			"nist_800_53": ["SC-7"],
		},
		"remediation_id": "REM_ec2_05",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_14 — Instances must be associated with an IAM instance profile
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.state.name == "running"
	not inst.iam_instance_profile
	result := {
		"check_id": "ec2_14",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"EC2 instance '%s' has no IAM instance profile attached",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.4"],
			"nist_800_53": ["AC-3"],
		},
		"remediation_id": "REM_ec2_14",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_15 — No security group allows unrestricted access on port 443
#               from 0.0.0.0/0 for internal-only services
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.ec2.security_groups
	sg.tags.exposure == "internal"
	some rule in sg.ip_permissions
	rule.from_port <= 443
	rule.to_port >= 443
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	result := {
		"check_id": "ec2_15",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Internal security group '%s' allows HTTPS from 0.0.0.0/0",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_ec2_15",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_16 — Security groups must not allow unrestricted outbound traffic
# ---------------------------------------------------------------------------
violations contains result if {
	some sg in input.ec2.security_groups
	some rule in sg.ip_permissions_egress
	rule.ip_protocol == "-1"
	some cidr in rule.ip_ranges
	cidr.cidr_ip == "0.0.0.0/0"
	sg.tags.environment == "production"
	result := {
		"check_id": "ec2_16",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production security group '%s' allows unrestricted outbound traffic",
			[sg.group_id],
		),
		"resource": sg.group_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.4"],
		},
		"remediation_id": "REM_ec2_16",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_17 — Key pairs must not be used for production instances
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.key_name != null
	inst.key_name != ""
	inst.tags.environment == "production"
	result := {
		"check_id": "ec2_17",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production EC2 instance '%s' uses key pair '%s' — use SSM Session Manager",
			[inst.instance_id, inst.key_name],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["5.5"],
			"nist_800_53": ["AC-17"],
		},
		"remediation_id": "REM_ec2_17",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_18 — Instances must not use deprecated/old generation instance types
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	inst.state.name == "running"
	startswith(inst.instance_type, "t1.")
	result := {
		"check_id": "ec2_18",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' uses deprecated instance type '%s'",
			[inst.instance_id, inst.instance_type],
		),
		"resource": inst.arn,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["CM-6"],
		},
		"remediation_id": "REM_ec2_18",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_19 — No unused elastic IPs (unassociated EIPs incur cost and risk)
# ---------------------------------------------------------------------------
violations contains result if {
	some eip in input.ec2.elastic_ips
	eip.instance_id == null
	eip.network_interface_id == null
	result := {
		"check_id": "ec2_19",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Elastic IP '%s' is not associated with any resource",
			[eip.public_ip],
		),
		"resource": eip.allocation_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_ec2_19",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_20 — AMIs used by instances must not be public/shared externally
# ---------------------------------------------------------------------------
violations contains result if {
	some ami in input.ec2.amis
	ami.public == true
	ami.owner_id == input.account_id
	result := {
		"check_id": "ec2_20",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"AMI '%s' owned by this account is publicly available",
			[ami.image_id],
		),
		"resource": ami.image_id,
		"domain": "compute",
		"service": "ec2",
		"compliance": {
			"cis_aws": ["2.2.3"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_ec2_20",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.ec2
	result := {
		"check_id": "ec2_00",
		"status": "error",
		"severity": "critical",
		"reason": "EC2 data missing from input — collector may have failed",
		"resource": "",
		"domain": "compute",
		"service": "ec2",
	}
}
