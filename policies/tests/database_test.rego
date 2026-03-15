package aws.data_protection.database_test

import data.aws.data_protection.database

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in database.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# Minimal compliant fixtures
# =========================================================================
_good_rds := {
	"db_instance_identifier": "my-db",
	"db_instance_arn": "arn:aws:rds:us-east-1:123456789012:db:my-db",
	"publicly_accessible": false,
	"storage_encrypted": true,
	"backup_retention_period": 14,
	"multi_az": true,
	"deletion_protection": true,
	"iam_database_authentication_enabled": true,
	"enabled_cloudwatch_logs_exports": ["audit", "error"],
	"auto_minor_version_upgrade": true,
	"db_instance_port": 15432,
	"tags": {"environment": "production"},
}

_good_snapshot := {
	"db_snapshot_identifier": "my-db-snap",
	"db_snapshot_arn": "arn:aws:rds:us-east-1:123456789012:snapshot:my-db-snap",
	"attributes": {"restore": ["123456789012"]},
}

_good_dynamo := {
	"table_name": "my-table",
	"table_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/my-table",
	"sse_description": {"status": "ENABLED"},
	"continuous_backups": {
		"point_in_time_recovery_description": {
			"point_in_time_recovery_status": "ENABLED",
		},
	},
	"deletion_protection_enabled": true,
	"billing_mode": "PAY_PER_REQUEST",
	"auto_scaling_enabled": false,
	"tags": {"environment": "production"},
	"resource_policy": {"Statement": []},
}

_good_cluster := {
	"db_cluster_identifier": "my-aurora",
	"db_cluster_arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-aurora",
	"publicly_accessible": false,
	"storage_encrypted": true,
	"deletion_protection": true,
	"iam_database_authentication_enabled": true,
	"backtrack_window": 86400,
	"engine": "aurora-mysql",
	"tags": {
		"environment": "production",
		"data_criticality": "high",
	},
}

_full_input := {
	"rds": {
		"db_instances": [_good_rds],
		"db_snapshots": [_good_snapshot],
		"db_clusters": [_good_cluster],
	},
	"dynamodb": {"tables": [_good_dynamo]},
}

# =========================================================================
# db_01 — RDS publicly accessible
# =========================================================================
test_db_01_alarm if {
	db := object.union(_good_rds, {"publicly_accessible": true})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_01"
}

test_db_01_compliant if {
	_violations_for("db_01", _full_input) == 0
}

# =========================================================================
# db_02 — RDS storage not encrypted
# =========================================================================
test_db_02_alarm if {
	db := object.union(_good_rds, {"storage_encrypted": false})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_02"
}

test_db_02_compliant if {
	_violations_for("db_02", _full_input) == 0
}

# =========================================================================
# db_03 — Backup retention < 7 days
# =========================================================================
test_db_03_alarm if {
	db := object.union(_good_rds, {"backup_retention_period": 3})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_03"
}

test_db_03_compliant if {
	_violations_for("db_03", _full_input) == 0
}

test_db_03_compliant_boundary if {
	db := object.union(_good_rds, {"backup_retention_period": 7})
	_violations_for("db_03", object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)) == 0
}

# =========================================================================
# db_04 — Multi-AZ not enabled in production
# =========================================================================
test_db_04_alarm if {
	db := object.union(_good_rds, {"multi_az": false})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_04"
}

test_db_04_compliant if {
	_violations_for("db_04", _full_input) == 0
}

test_db_04_compliant_dev if {
	db := object.union(_good_rds, {
		"multi_az": false,
		"tags": {"environment": "development"},
	})
	_violations_for("db_04", object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)) == 0
}

# =========================================================================
# db_05 — Deletion protection disabled in production
# =========================================================================
test_db_05_alarm if {
	db := object.union(_good_rds, {"deletion_protection": false})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_05"
}

test_db_05_compliant if {
	_violations_for("db_05", _full_input) == 0
}

# =========================================================================
# db_06 — IAM authentication not enabled
# =========================================================================
test_db_06_alarm if {
	db := object.union(_good_rds, {
		"iam_database_authentication_enabled": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_06"
}

test_db_06_compliant if {
	_violations_for("db_06", _full_input) == 0
}

# =========================================================================
# db_07 — Public snapshot
# =========================================================================
test_db_07_alarm if {
	snap := object.union(_good_snapshot, {
		"attributes": {"restore": ["all"]},
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_snapshots": [snap]})},
	)
	some v in r
	v.check_id == "db_07"
}

test_db_07_compliant if {
	_violations_for("db_07", _full_input) == 0
}

# =========================================================================
# db_08 — No CloudWatch log exports
# =========================================================================
test_db_08_alarm if {
	db := object.union(_good_rds, {
		"enabled_cloudwatch_logs_exports": [],
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_08"
}

test_db_08_compliant if {
	_violations_for("db_08", _full_input) == 0
}

# =========================================================================
# db_09 — Auto minor version upgrade disabled
# =========================================================================
test_db_09_alarm if {
	db := object.union(_good_rds, {
		"auto_minor_version_upgrade": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_09"
}

test_db_09_compliant if {
	_violations_for("db_09", _full_input) == 0
}

# =========================================================================
# db_10 — Default database port
# =========================================================================
test_db_10_alarm_mysql if {
	db := object.union(_good_rds, {"db_instance_port": 3306})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_10"
}

test_db_10_alarm_postgres if {
	db := object.union(_good_rds, {"db_instance_port": 5432})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_instances": [db]})},
	)
	some v in r
	v.check_id == "db_10"
}

test_db_10_compliant if {
	_violations_for("db_10", _full_input) == 0
}

# =========================================================================
# db_11 — DynamoDB KMS encryption
# =========================================================================
test_db_11_alarm if {
	tbl := object.union(_good_dynamo, {
		"sse_description": {"status": "DISABLED"},
	})
	r := database.violations with input as object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)
	some v in r
	v.check_id == "db_11"
}

test_db_11_compliant if {
	_violations_for("db_11", _full_input) == 0
}

# =========================================================================
# db_12 — DynamoDB PITR
# =========================================================================
test_db_12_alarm if {
	tbl := object.union(_good_dynamo, {
		"continuous_backups": {
			"point_in_time_recovery_description": {
				"point_in_time_recovery_status": "DISABLED",
			},
		},
	})
	r := database.violations with input as object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)
	some v in r
	v.check_id == "db_12"
}

test_db_12_compliant if {
	_violations_for("db_12", _full_input) == 0
}

# =========================================================================
# db_13 — DynamoDB deletion protection (production)
# =========================================================================
test_db_13_alarm if {
	tbl := object.union(_good_dynamo, {
		"deletion_protection_enabled": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)
	some v in r
	v.check_id == "db_13"
}

test_db_13_compliant if {
	_violations_for("db_13", _full_input) == 0
}

test_db_13_compliant_dev if {
	tbl := object.union(_good_dynamo, {
		"deletion_protection_enabled": false,
		"tags": {"environment": "development"},
	})
	_violations_for("db_13", object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)) == 0
}

# =========================================================================
# db_14 — DynamoDB public access
# =========================================================================
test_db_14_alarm if {
	tbl := object.union(_good_dynamo, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "dynamodb:GetItem",
		}]},
	})
	r := database.violations with input as object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)
	some v in r
	v.check_id == "db_14"
}

test_db_14_compliant if {
	_violations_for("db_14", _full_input) == 0
}

test_db_14_compliant_with_condition if {
	tbl := object.union(_good_dynamo, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "dynamodb:GetItem",
			"Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
		}]},
	})
	_violations_for("db_14", object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)) == 0
}

# =========================================================================
# db_15 — DynamoDB auto-scaling (provisioned, production)
# =========================================================================
test_db_15_alarm if {
	tbl := object.union(_good_dynamo, {
		"billing_mode": "PROVISIONED",
		"auto_scaling_enabled": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)
	some v in r
	v.check_id == "db_15"
}

test_db_15_compliant_pay_per_request if {
	_violations_for("db_15", _full_input) == 0
}

test_db_15_compliant_autoscaling_on if {
	tbl := object.union(_good_dynamo, {
		"billing_mode": "PROVISIONED",
		"auto_scaling_enabled": true,
	})
	_violations_for("db_15", object.union(
		_full_input,
		{"dynamodb": {"tables": [tbl]}},
	)) == 0
}

# =========================================================================
# db_16 — Aurora cluster publicly accessible
# =========================================================================
test_db_16_alarm if {
	cluster := object.union(_good_cluster, {
		"publicly_accessible": true,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)
	some v in r
	v.check_id == "db_16"
}

test_db_16_compliant if {
	_violations_for("db_16", _full_input) == 0
}

# =========================================================================
# db_17 — Aurora storage not encrypted
# =========================================================================
test_db_17_alarm if {
	cluster := object.union(_good_cluster, {
		"storage_encrypted": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)
	some v in r
	v.check_id == "db_17"
}

test_db_17_compliant if {
	_violations_for("db_17", _full_input) == 0
}

# =========================================================================
# db_18 — Aurora deletion protection (production)
# =========================================================================
test_db_18_alarm if {
	cluster := object.union(_good_cluster, {
		"deletion_protection": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)
	some v in r
	v.check_id == "db_18"
}

test_db_18_compliant if {
	_violations_for("db_18", _full_input) == 0
}

test_db_18_compliant_dev if {
	cluster := object.union(_good_cluster, {
		"deletion_protection": false,
		"tags": object.union(_good_cluster.tags, {
			"environment": "development",
		}),
	})
	_violations_for("db_18", object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)) == 0
}

# =========================================================================
# db_19 — Aurora Backtrack not enabled (MySQL, critical)
# =========================================================================
test_db_19_alarm if {
	cluster := object.union(_good_cluster, {"backtrack_window": 0})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)
	some v in r
	v.check_id == "db_19"
}

test_db_19_compliant if {
	_violations_for("db_19", _full_input) == 0
}

test_db_19_compliant_postgres if {
	cluster := object.union(_good_cluster, {
		"backtrack_window": 0,
		"engine": "aurora-postgresql",
	})
	_violations_for("db_19", object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)) == 0
}

test_db_19_compliant_low_criticality if {
	cluster := object.union(_good_cluster, {
		"backtrack_window": 0,
		"tags": object.union(_good_cluster.tags, {
			"data_criticality": "low",
		}),
	})
	_violations_for("db_19", object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)) == 0
}

# =========================================================================
# db_20 — Aurora IAM authentication
# =========================================================================
test_db_20_alarm if {
	cluster := object.union(_good_cluster, {
		"iam_database_authentication_enabled": false,
	})
	r := database.violations with input as object.union(
		_full_input,
		{"rds": object.union(_full_input.rds, {"db_clusters": [cluster]})},
	)
	some v in r
	v.check_id == "db_20"
}

test_db_20_compliant if {
	_violations_for("db_20", _full_input) == 0
}

# =========================================================================
# Error handlers
# =========================================================================
test_error_rds_missing if {
	r := database.error with input as {
		"dynamodb": {"tables": [_good_dynamo]},
	}
	some e in r
	e.check_id == "db_00_rds"
}

test_error_dynamodb_missing if {
	r := database.error with input as {
		"rds": _full_input.rds,
	}
	some e in r
	e.check_id == "db_00_dynamodb"
}
