package aws.cross_resource.capital_one_test

import data.aws.cross_resource.capital_one

test_alarm_capital_one_pattern if {
	result := capital_one.violations with input as {"ec2": {"instances": [{
		"instance_id": "i-1",
		"arn": "arn:1",
		"public_ip": "1.2.3.4",
		"iam_role": {
			"role_name": "OverpermissiveRole",
			"attached_policies": [{"policy_name": "AdministratorAccess"}],
		},
		"metadata_options": {"http_tokens": "optional"},
	}]}}
	count(result) == 1
}

test_no_alarm_no_public_ip if {
	result := capital_one.violations with input as {"ec2": {"instances": [{
		"instance_id": "i-2",
		"arn": "arn:2",
		"public_ip": null,
		"iam_role": {
			"role_name": "SomeRole",
			"attached_policies": [{"policy_name": "AdministratorAccess"}],
		},
		"metadata_options": {"http_tokens": "optional"},
	}]}}
	count(result) == 0
}

test_no_alarm_imdsv2_enabled if {
	result := capital_one.violations with input as {"ec2": {"instances": [{
		"instance_id": "i-3",
		"arn": "arn:3",
		"public_ip": "1.2.3.4",
		"iam_role": {
			"role_name": "SomeRole",
			"attached_policies": [{"policy_name": "AdministratorAccess"}],
		},
		"metadata_options": {"http_tokens": "required"},
	}]}}
	count(result) == 0
}
