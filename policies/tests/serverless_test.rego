package aws.compute.serverless_test

import data.aws.compute.serverless

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in serverless.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# Minimal compliant fixtures
# =========================================================================
_good_lambda := {
	"function_name": "my-func",
	"function_arn": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
	"tracing_config": {"mode": "Active"},
	"runtime": "python3.12",
	"environment": {"variables": {}},
	"kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/abc",
	"policy": {"Statement": []},
	"role_policies": [{"policy_name": "BasicExecution"}],
}

_good_ecs_td := {
	"task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
	"network_mode": "awsvpc",
	"container_definitions": [{
		"name": "app",
		"privileged": false,
		"readonly_root_filesystem": true,
		"log_configuration": {"log_driver": "awslogs"},
	}],
}

_good_ecs_cluster := {
	"cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster",
	"settings": [{"name": "containerInsights", "value": "enabled"}],
}

_good_eks_cluster := {
	"name": "my-eks",
	"arn": "arn:aws:eks:us-east-1:123456789012:cluster/my-eks",
	"version": "1.29",
	"resources_vpc_config": {
		"endpoint_public_access": false,
		"public_access_cidrs": [],
	},
	"encryption_config": [{"resources": ["secrets"], "provider": {"key_arn": "arn:aws:kms:us-east-1:123456789012:key/abc"}}],
	"logging": {"cluster_logging": [{"types": ["audit", "api"], "enabled": true}]},
}

_good_eks_ng := {
	"node_group_name": "my-ng",
	"node_group_arn": "arn:aws:eks:us-east-1:123456789012:nodegroup/my-eks/my-ng/abc",
	"subnets": [{"subnet_id": "subnet-abc", "map_public_ip_on_launch": false}],
}

_good_ecr_repo := {
	"repository_name": "my-repo",
	"repository_arn": "arn:aws:ecr:us-east-1:123456789012:repository/my-repo",
	"image_scanning_configuration": {"scan_on_push": true},
	"repository_visibility": "private",
	"image_tag_mutability": "IMMUTABLE",
	"lifecycle_policy": {"rules": [{"rulePriority": 1}]},
	"encryption_configuration": {"encryption_type": "KMS"},
	"tags": {"data_classification": "public"},
}

# Full compliant input
_full_input := {
	"lambda_functions": [_good_lambda],
	"ecs": {
		"task_definitions": [_good_ecs_td],
		"clusters": [_good_ecs_cluster],
	},
	"eks": {
		"clusters": [_good_eks_cluster],
		"node_groups": [_good_eks_ng],
		"eol_versions": ["1.24", "1.25"],
	},
	"ecr": {"repositories": [_good_ecr_repo]},
}

# =========================================================================
# serverless_01 — Lambda X-Ray tracing
# =========================================================================
test_serverless_01_alarm if {
	fn := object.union(_good_lambda, {
		"tracing_config": {"mode": "PassThrough"},
	})
	r := serverless.violations with input as {
		"lambda_functions": [fn],
		"ecs": _full_input.ecs,
		"eks": _full_input.eks,
		"ecr": _full_input.ecr,
	}
	some v in r
	v.check_id == "serverless_lambda_xray"
}

test_serverless_01_compliant if {
	_violations_for("serverless_lambda_xray", _full_input) == 0
}

# =========================================================================
# serverless_02 — Lambda env vars encrypted with KMS
# =========================================================================
test_serverless_02_alarm if {
	fn := object.union(
		object.remove(_good_lambda, ["kms_key_arn"]),
		{"environment": {"variables": {"SECRET": "val"}}},
	)
	r := serverless.violations with input as object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)
	some v in r
	v.check_id == "serverless_lambda_kms_env"
}

test_serverless_02_compliant_has_kms if {
	_violations_for("serverless_lambda_kms_env", _full_input) == 0
}

test_serverless_02_compliant_no_vars if {
	fn := object.union(
		object.remove(_good_lambda, ["kms_key_arn"]),
		{"environment": {"variables": {}}},
	)
	_violations_for("serverless_lambda_kms_env", object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)) == 0
}

# =========================================================================
# serverless_03 — Lambda deprecated runtime
# =========================================================================
test_serverless_03_alarm if {
	fn := object.union(_good_lambda, {"runtime": "python2.7"})
	r := serverless.violations with input as object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)
	some v in r
	v.check_id == "serverless_lambda_runtime"
}

test_serverless_03_alarm_nodejs if {
	fn := object.union(_good_lambda, {"runtime": "nodejs8.10"})
	r := serverless.violations with input as object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)
	some v in r
	v.check_id == "serverless_lambda_runtime"
}

test_serverless_03_compliant if {
	_violations_for("serverless_lambda_runtime", _full_input) == 0
}

# =========================================================================
# serverless_04 — Lambda public invocation
# =========================================================================
test_serverless_04_alarm if {
	fn := object.union(_good_lambda, {
		"policy": {"Statement": [
			{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"},
		]},
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)
	some v in r
	v.check_id == "serverless_lambda_no_public_invoke"
}

test_serverless_04_compliant if {
	_violations_for("serverless_lambda_no_public_invoke", _full_input) == 0
}

test_serverless_04_compliant_deny if {
	fn := object.union(_good_lambda, {
		"policy": {"Statement": [
			{"Effect": "Deny", "Principal": "*", "Action": "lambda:InvokeFunction"},
		]},
	})
	_violations_for("serverless_lambda_no_public_invoke", object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)) == 0
}

# =========================================================================
# serverless_05 — Lambda AdministratorAccess
# =========================================================================
test_serverless_05_alarm if {
	fn := object.union(_good_lambda, {
		"role_policies": [{"policy_name": "AdministratorAccess"}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"lambda_functions": [fn]},
	)
	some v in r
	v.check_id == "serverless_lambda_no_admin_role"
}

test_serverless_05_compliant if {
	_violations_for("serverless_lambda_no_admin_role", _full_input) == 0
}

# =========================================================================
# serverless_06 — ECS privileged container
# =========================================================================
test_serverless_06_alarm if {
	td := object.union(_good_ecs_td, {
		"container_definitions": [{
			"name": "app",
			"privileged": true,
			"readonly_root_filesystem": true,
			"log_configuration": {"log_driver": "awslogs"},
		}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecs": object.union(_full_input.ecs, {"task_definitions": [td]})},
	)
	some v in r
	v.check_id == "serverless_ecs_no_privileged"
}

test_serverless_06_compliant if {
	_violations_for("serverless_ecs_no_privileged", _full_input) == 0
}

# =========================================================================
# serverless_07 — ECS read-only root filesystem
# =========================================================================
test_serverless_07_alarm if {
	td := object.union(_good_ecs_td, {
		"container_definitions": [{
			"name": "app",
			"privileged": false,
			"readonly_root_filesystem": false,
			"log_configuration": {"log_driver": "awslogs"},
		}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecs": object.union(_full_input.ecs, {"task_definitions": [td]})},
	)
	some v in r
	v.check_id == "serverless_ecs_readonly_root"
}

test_serverless_07_compliant if {
	_violations_for("serverless_ecs_readonly_root", _full_input) == 0
}

# =========================================================================
# serverless_08 — ECS awslogs driver
# =========================================================================
test_serverless_08_alarm if {
	td := object.union(_good_ecs_td, {
		"container_definitions": [{
			"name": "app",
			"privileged": false,
			"readonly_root_filesystem": true,
			"log_configuration": {"log_driver": "json-file"},
		}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecs": object.union(_full_input.ecs, {"task_definitions": [td]})},
	)
	some v in r
	v.check_id == "serverless_ecs_cloudwatch_logs"
}

test_serverless_08_compliant if {
	_violations_for("serverless_ecs_cloudwatch_logs", _full_input) == 0
}

# =========================================================================
# serverless_09 — ECS host network mode
# =========================================================================
test_serverless_09_alarm if {
	td := object.union(_good_ecs_td, {"network_mode": "host"})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecs": object.union(_full_input.ecs, {"task_definitions": [td]})},
	)
	some v in r
	v.check_id == "serverless_ecs_no_host_network"
}

test_serverless_09_compliant if {
	_violations_for("serverless_ecs_no_host_network", _full_input) == 0
}

# =========================================================================
# serverless_10 — ECS Container Insights
# =========================================================================
test_serverless_10_alarm if {
	cluster := object.union(_good_ecs_cluster, {
		"settings": [{"name": "containerInsights", "value": "disabled"}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecs": object.union(_full_input.ecs, {"clusters": [cluster]})},
	)
	some v in r
	v.check_id == "serverless_ecs_container_insights"
}

test_serverless_10_compliant if {
	_violations_for("serverless_ecs_container_insights", _full_input) == 0
}

# =========================================================================
# serverless_11 — EKS public API endpoint
# =========================================================================
test_serverless_11_alarm if {
	cluster := object.union(_good_eks_cluster, {
		"resources_vpc_config": {
			"endpoint_public_access": true,
			"public_access_cidrs": ["0.0.0.0/0"],
		},
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"clusters": [cluster]})},
	)
	some v in r
	v.check_id == "serverless_eks_private_endpoint"
}

test_serverless_11_compliant if {
	_violations_for("serverless_eks_private_endpoint", _full_input) == 0
}

test_serverless_11_compliant_restricted_cidr if {
	cluster := object.union(_good_eks_cluster, {
		"resources_vpc_config": {
			"endpoint_public_access": true,
			"public_access_cidrs": ["10.0.0.0/8"],
		},
	})
	_violations_for("serverless_eks_private_endpoint", object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"clusters": [cluster]})},
	)) == 0
}

# =========================================================================
# serverless_12 — EKS secrets encryption
# =========================================================================
test_serverless_12_alarm if {
	cluster := object.union(_good_eks_cluster, {
		"encryption_config": [{"resources": ["configmaps"], "provider": {"key_arn": "arn:aws:kms:us-east-1:123456789012:key/abc"}}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"clusters": [cluster]})},
	)
	some v in r
	v.check_id == "serverless_eks_secrets_encryption"
}

test_serverless_12_alarm_empty if {
	cluster := object.union(_good_eks_cluster, {
		"encryption_config": [],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"clusters": [cluster]})},
	)
	some v in r
	v.check_id == "serverless_eks_secrets_encryption"
}

test_serverless_12_compliant if {
	_violations_for("serverless_eks_secrets_encryption", _full_input) == 0
}

# =========================================================================
# serverless_13 — EKS audit logs
# =========================================================================
test_serverless_13_alarm if {
	cluster := object.union(_good_eks_cluster, {
		"logging": {"cluster_logging": [{"types": ["api", "scheduler"], "enabled": true}]},
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"clusters": [cluster]})},
	)
	some v in r
	v.check_id == "serverless_eks_audit_logs"
}

test_serverless_13_compliant if {
	_violations_for("serverless_eks_audit_logs", _full_input) == 0
}

# =========================================================================
# serverless_14 — EKS node groups in private subnets
# =========================================================================
test_serverless_14_alarm if {
	ng := object.union(_good_eks_ng, {
		"subnets": [{"subnet_id": "subnet-pub", "map_public_ip_on_launch": true}],
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"node_groups": [ng]})},
	)
	some v in r
	v.check_id == "serverless_eks_private_subnets"
}

test_serverless_14_compliant if {
	_violations_for("serverless_eks_private_subnets", _full_input) == 0
}

# =========================================================================
# serverless_15 — EKS EOL Kubernetes version
# =========================================================================
test_serverless_15_alarm if {
	cluster := object.union(_good_eks_cluster, {"version": "1.24"})
	r := serverless.violations with input as object.union(
		_full_input,
		{"eks": object.union(_full_input.eks, {"clusters": [cluster]})},
	)
	some v in r
	v.check_id == "serverless_eks_version_current"
}

test_serverless_15_compliant if {
	_violations_for("serverless_eks_version_current", _full_input) == 0
}

# =========================================================================
# serverless_16 — ECR scan on push
# =========================================================================
test_serverless_16_alarm if {
	repo := object.union(_good_ecr_repo, {
		"image_scanning_configuration": {"scan_on_push": false},
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecr": {"repositories": [repo]}},
	)
	some v in r
	v.check_id == "serverless_ecr_image_scanning"
}

test_serverless_16_compliant if {
	_violations_for("serverless_ecr_image_scanning", _full_input) == 0
}

# =========================================================================
# serverless_17 — ECR public repository
# =========================================================================
test_serverless_17_alarm if {
	repo := object.union(_good_ecr_repo, {
		"repository_visibility": "public",
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecr": {"repositories": [repo]}},
	)
	some v in r
	v.check_id == "serverless_ecr_private"
}

test_serverless_17_compliant if {
	_violations_for("serverless_ecr_private", _full_input) == 0
}

# =========================================================================
# serverless_18 — ECR tag immutability
# =========================================================================
test_serverless_18_alarm if {
	repo := object.union(_good_ecr_repo, {
		"image_tag_mutability": "MUTABLE",
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecr": {"repositories": [repo]}},
	)
	some v in r
	v.check_id == "serverless_ecr_tag_immutability"
}

test_serverless_18_compliant if {
	_violations_for("serverless_ecr_tag_immutability", _full_input) == 0
}

# =========================================================================
# serverless_19 — ECR lifecycle policy
# =========================================================================
test_serverless_19_alarm if {
	repo := object.remove(_good_ecr_repo, ["lifecycle_policy"])
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecr": {"repositories": [repo]}},
	)
	some v in r
	v.check_id == "serverless_ecr_lifecycle_policy"
}

test_serverless_19_compliant if {
	_violations_for("serverless_ecr_lifecycle_policy", _full_input) == 0
}

# =========================================================================
# serverless_20 — ECR KMS encryption for sensitive repos
# =========================================================================
test_serverless_20_alarm if {
	repo := object.union(_good_ecr_repo, {
		"encryption_configuration": {"encryption_type": "AES256"},
		"tags": {"data_classification": "sensitive"},
	})
	r := serverless.violations with input as object.union(
		_full_input,
		{"ecr": {"repositories": [repo]}},
	)
	some v in r
	v.check_id == "serverless_ecr_kms_encryption"
}

test_serverless_20_compliant_kms if {
	_violations_for("serverless_ecr_kms_encryption", _full_input) == 0
}

test_serverless_20_compliant_not_sensitive if {
	repo := object.union(_good_ecr_repo, {
		"encryption_configuration": {"encryption_type": "AES256"},
		"tags": {"data_classification": "public"},
	})
	_violations_for("serverless_ecr_kms_encryption", object.union(
		_full_input,
		{"ecr": {"repositories": [repo]}},
	)) == 0
}

# =========================================================================
# Error handlers
# =========================================================================
test_error_lambda_missing if {
	r := serverless.error with input as {
		"ecs": _full_input.ecs,
		"eks": _full_input.eks,
		"ecr": _full_input.ecr,
	}
	some e in r
	e.check_id == "serverless_lambda_error"
}

test_error_ecs_missing if {
	r := serverless.error with input as {
		"lambda_functions": [_good_lambda],
		"eks": _full_input.eks,
		"ecr": _full_input.ecr,
	}
	some e in r
	e.check_id == "serverless_ecs_error"
}

test_error_eks_missing if {
	r := serverless.error with input as {
		"lambda_functions": [_good_lambda],
		"ecs": _full_input.ecs,
		"ecr": _full_input.ecr,
	}
	some e in r
	e.check_id == "serverless_eks_error"
}

test_error_ecr_missing if {
	r := serverless.error with input as {
		"lambda_functions": [_good_lambda],
		"ecs": _full_input.ecs,
		"eks": _full_input.eks,
	}
	some e in r
	e.check_id == "serverless_ecr_error"
}
