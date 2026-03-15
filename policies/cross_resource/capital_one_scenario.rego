package aws.cross_resource.capital_one

violations contains result if {
	some instance in input.ec2.instances
	instance.public_ip != null
	role := instance.iam_role
	role != null
	some policy in role.attached_policies
	is_overpermissive(policy.policy_name)
	instance.metadata_options.http_tokens != "required"
	result := {
		"check_id": "CROSS_01",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"EC2 %s has public IP + overpermissive IAM role '%s' + IMDSv1 (Capital One breach pattern)",
			[instance.instance_id, role.role_name],
		),
		"resource": instance.arn,
		"domain": "cross_resource",
		"compliance": {
			"cis_aws": ["1.16", "5.2"],
			"nist_800_53": ["AC-6", "AC-4"],
		},
		"remediation_id": "REM_CROSS_01",
	}
}

is_overpermissive(name) if {
	overpermissive_patterns := [
		"AdministratorAccess",
		"AmazonS3FullAccess",
		"PowerUserAccess",
		"IAMFullAccess",
	]
	name == overpermissive_patterns[_]
}
