package aws.compute.serverless

import future.keywords.if
import future.keywords.in

# =============================================================================
# SERVERLESS POLICY — covers Lambda, ECS, EKS, and ECR
# Rule naming: serverless_01 … serverless_20
# =============================================================================

deprecated_runtimes := {
	"nodejs6.10", "nodejs8.10", "nodejs10.x",
	"python2.7", "python3.6", "ruby2.5",
	"java8", "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1",
}

# ---------------------------------------------------------------------------
# Rule serverless_01 — Lambda: X-Ray active tracing must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some fn in input.lambda_functions
	fn.tracing_config.mode != "Active"
	result := {
		"check_id": "serverless_01",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Lambda function '%s' does not have X-Ray active tracing enabled",
			[fn.function_name],
		),
		"resource": fn.function_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_serverless_01",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_02 — Lambda: environment variables must be encrypted with KMS
# ---------------------------------------------------------------------------
violations contains result if {
	some fn in input.lambda_functions
	count(fn.environment.variables) > 0
	not fn.kms_key_arn
	result := {
		"check_id": "serverless_02",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Lambda function '%s' has env vars but no KMS key configured",
			[fn.function_name],
		),
		"resource": fn.function_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"cis_aws": ["3.11"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
		},
		"remediation_id": "REM_serverless_02",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_03 — Lambda: must not use a deprecated runtime
# ---------------------------------------------------------------------------
violations contains result if {
	some fn in input.lambda_functions
	fn.runtime in deprecated_runtimes
	result := {
		"check_id": "serverless_03",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Lambda function '%s' uses deprecated runtime '%s'",
			[fn.function_name, fn.runtime],
		),
		"resource": fn.function_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SI-2"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_serverless_03",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_04 — Lambda: resource policy must not allow public invocation
# ---------------------------------------------------------------------------
violations contains result if {
	some fn in input.lambda_functions
	some stmt in fn.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	result := {
		"check_id": "serverless_04",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Lambda function '%s' resource policy allows public invocation",
			[fn.function_name],
		),
		"resource": fn.function_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_serverless_04",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_05 — Lambda: execution role must not have AdministratorAccess
# ---------------------------------------------------------------------------
violations contains result if {
	some fn in input.lambda_functions
	some policy in fn.role_policies
	policy.policy_name == "AdministratorAccess"
	result := {
		"check_id": "serverless_05",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Lambda function '%s' execution role has AdministratorAccess",
			[fn.function_name],
		),
		"resource": fn.function_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"cis_aws": ["1.16"],
			"nist_800_53": ["AC-6(5)"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_serverless_05",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_06 — ECS: containers must not run in privileged mode
# ---------------------------------------------------------------------------
violations contains result if {
	some td in input.ecs.task_definitions
	some container in td.container_definitions
	container.privileged == true
	result := {
		"check_id": "serverless_06",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"ECS task '%s' container '%s' runs in privileged mode",
			[td.task_definition_arn, container.name],
		),
		"resource": td.task_definition_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["AC-6(5)"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_serverless_06",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_07 — ECS: root filesystem must be read-only
# ---------------------------------------------------------------------------
violations contains result if {
	some td in input.ecs.task_definitions
	some container in td.container_definitions
	container.readonly_root_filesystem == false
	result := {
		"check_id": "serverless_07",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"ECS container '%s' in task '%s' does not use read-only root filesystem",
			[container.name, td.task_definition_arn],
		),
		"resource": td.task_definition_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["CM-7"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_serverless_07",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_08 — ECS: containers must use awslogs (CloudWatch Logs) driver
# ---------------------------------------------------------------------------
violations contains result if {
	some td in input.ecs.task_definitions
	some container in td.container_definitions
	container.log_configuration.log_driver != "awslogs"
	result := {
		"check_id": "serverless_08",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"ECS container '%s' in task '%s' does not use awslogs driver",
			[container.name, td.task_definition_arn],
		),
		"resource": td.task_definition_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["AU-9"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_serverless_08",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_09 — ECS: task definition must not use host network mode
# ---------------------------------------------------------------------------
violations contains result if {
	some td in input.ecs.task_definitions
	td.network_mode == "host"
	result := {
		"check_id": "serverless_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"ECS task definition '%s' uses host network mode",
			[td.task_definition_arn],
		),
		"resource": td.task_definition_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_serverless_09",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_10 — ECS: Container Insights must be enabled on clusters
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.ecs.clusters
	cluster.settings[_].name == "containerInsights"
	cluster.settings[_].value != "enabled"
	result := {
		"check_id": "serverless_10",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"ECS cluster '%s' does not have Container Insights enabled",
			[cluster.cluster_arn],
		),
		"resource": cluster.cluster_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["AU-12"],
		},
		"remediation_id": "REM_serverless_10",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_11 — EKS: cluster API endpoint must not be public
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.eks.clusters
	cluster.resources_vpc_config.endpoint_public_access == true
	cluster.resources_vpc_config.public_access_cidrs[_] == "0.0.0.0/0"
	result := {
		"check_id": "serverless_11",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"EKS cluster '%s' API endpoint is publicly accessible from 0.0.0.0/0",
			[cluster.name],
		),
		"resource": cluster.arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"cis_aws": ["5.4"],
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_serverless_11",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_12 — EKS: secrets encryption must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.eks.clusters
	encryption_configs := [c | some c in cluster.encryption_config; "secrets" in c.resources]
	count(encryption_configs) == 0
	result := {
		"check_id": "serverless_12",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EKS cluster '%s' does not have secrets encryption configured",
			[cluster.name],
		),
		"resource": cluster.arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"cis_aws": ["5.3"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
		},
		"remediation_id": "REM_serverless_12",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_13 — EKS: audit logs must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.eks.clusters
	audit_logs := [l | some l in cluster.logging.cluster_logging[_].types; l == "audit"]
	count(audit_logs) == 0
	result := {
		"check_id": "serverless_13",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EKS cluster '%s' does not have audit logging enabled",
			[cluster.name],
		),
		"resource": cluster.arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"cis_aws": ["5.1"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_serverless_13",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_14 — EKS: node groups must use private subnets
# ---------------------------------------------------------------------------
violations contains result if {
	some ng in input.eks.node_groups
	some subnet in ng.subnets
	subnet.map_public_ip_on_launch == true
	result := {
		"check_id": "serverless_14",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EKS node group '%s' nodes are in a public subnet",
			[ng.node_group_name],
		),
		"resource": ng.node_group_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SC-7"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_serverless_14",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_15 — EKS: Kubernetes version must not be end-of-life
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.eks.clusters
	cluster.version in input.eks.eol_versions
	result := {
		"check_id": "serverless_15",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EKS cluster '%s' uses end-of-life Kubernetes version '%s'",
			[cluster.name, cluster.version],
		),
		"resource": cluster.arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SI-2"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_serverless_15",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_16 — ECR: image scanning must be enabled on repositories
# ---------------------------------------------------------------------------
violations contains result if {
	some repo in input.ecr.repositories
	repo.image_scanning_configuration.scan_on_push == false
	result := {
		"check_id": "serverless_16",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"ECR repository '%s' does not have scan-on-push enabled",
			[repo.repository_name],
		),
		"resource": repo.repository_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SI-3"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_serverless_16",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_17 — ECR: repositories must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some repo in input.ecr.repositories
	repo.repository_visibility == "public"
	result := {
		"check_id": "serverless_17",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"ECR repository '%s' is publicly accessible",
			[repo.repository_name],
		),
		"resource": repo.repository_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_serverless_17",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_18 — ECR: image tag immutability must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some repo in input.ecr.repositories
	repo.image_tag_mutability != "IMMUTABLE"
	result := {
		"check_id": "serverless_18",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"ECR repository '%s' does not have image tag immutability enabled",
			[repo.repository_name],
		),
		"resource": repo.repository_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SI-7"],
			"pci_dss": ["6.3.2"],
		},
		"remediation_id": "REM_serverless_18",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_19 — ECR: lifecycle policy must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	some repo in input.ecr.repositories
	not repo.lifecycle_policy
	result := {
		"check_id": "serverless_19",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"ECR repository '%s' has no lifecycle policy — old images will accumulate",
			[repo.repository_name],
		),
		"resource": repo.repository_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SI-12"],
		},
		"remediation_id": "REM_serverless_19",
	}
}

# ---------------------------------------------------------------------------
# Rule serverless_20 — ECR: repositories must be encrypted with KMS
# ---------------------------------------------------------------------------
violations contains result if {
	some repo in input.ecr.repositories
	repo.encryption_configuration.encryption_type != "KMS"
	repo.tags.data_classification == "sensitive"
	result := {
		"check_id": "serverless_20",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Sensitive ECR repository '%s' is not encrypted with KMS",
			[repo.repository_name],
		),
		"resource": repo.repository_arn,
		"domain": "compute",
		"service": "serverless",
		"compliance": {
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
		},
		"remediation_id": "REM_serverless_20",
	}
}

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
error contains result if {
	not input.lambda_functions
	result := {
		"check_id": "serverless_00_lambda",
		"status": "error",
		"severity": "critical",
		"reason": "Lambda data missing from input — collector may have failed",
		"resource": "",
		"domain": "compute",
		"service": "serverless",
	}
}

error contains result if {
	not input.ecs
	result := {
		"check_id": "serverless_00_ecs",
		"status": "error",
		"severity": "critical",
		"reason": "ECS data missing from input — collector may have failed",
		"resource": "",
		"domain": "compute",
		"service": "serverless",
	}
}

error contains result if {
	not input.eks
	result := {
		"check_id": "serverless_00_eks",
		"status": "error",
		"severity": "critical",
		"reason": "EKS data missing from input — collector may have failed",
		"resource": "",
		"domain": "compute",
		"service": "serverless",
	}
}

error contains result if {
	not input.ecr
	result := {
		"check_id": "serverless_00_ecr",
		"status": "error",
		"severity": "critical",
		"reason": "ECR data missing from input — collector may have failed",
		"resource": "",
		"domain": "compute",
		"service": "serverless",
	}
}
