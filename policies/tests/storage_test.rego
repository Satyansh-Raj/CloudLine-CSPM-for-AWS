package aws.data_protection.storage_test

import data.aws.data_protection.storage

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in storage.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# Minimal compliant fixtures
# =========================================================================
_good_vol := {
	"volume_id": "vol-abc123",
	"encrypted": true,
	"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
	"state": "in-use",
	"days_since_detached": 0,
	"volume_type": "gp3",
	"tags": {
		"environment": "production",
		"data_classification": "sensitive",
	},
}

_good_snap := {
	"snapshot_id": "snap-abc123",
	"encrypted": true,
	"owner_id": "123456789012",
	"create_volume_permissions": [{"user_id": "999888777666"}],
}

_good_efs := {
	"file_system_id": "fs-abc123",
	"file_system_arn": "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-abc123",
	"encrypted": true,
	"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
	"transit_encryption_enabled": true,
	"backup_policy": {"status": "ENABLED"},
	"resource_policy": {"Statement": []},
	"lifecycle_policies": [{"transition_to_ia": "AFTER_30_DAYS"}],
	"throughput_mode": "elastic",
	"size_in_bytes": {"value_in_ia": 500000000},
	"replication_configuration": {
		"destinations": [{"region": "us-west-2"}],
	},
	"tags": {
		"owner": "platform-team",
		"data_classification": "sensitive",
		"data_criticality": "high",
		"environment": "production",
	},
}

_good_ap := {
	"access_point_id": "fsap-abc123",
	"access_point_arn": "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-abc123",
	"posix_user": {"uid": 1000, "gid": 1000},
}

_good_mt := {
	"mount_target_id": "fsmt-abc123",
	"subnet_map_public_ip": false,
}

_full_input := {
	"ebs": {
		"volumes": [_good_vol],
		"snapshots": [_good_snap],
		"default_encryption_enabled": true,
		"lifecycle_policies_count": 2,
		"approved_sharing_accounts": ["999888777666"],
	},
	"efs": {
		"file_systems": [_good_efs],
		"access_points": [_good_ap],
		"mount_targets": [_good_mt],
	},
	"account_id": "123456789012",
	"region": "us-east-1",
}

# =========================================================================
# storage_01 — EBS volume not encrypted
# =========================================================================
test_storage_01_alarm if {
	vol := object.union(_good_vol, {"encrypted": false})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)
	some v in r
	v.check_id == "storage_ebs_encryption"
}

test_storage_01_compliant if {
	_violations_for("storage_ebs_encryption", _full_input) == 0
}

# =========================================================================
# storage_02 — EBS default encryption disabled
# =========================================================================
test_storage_02_alarm if {
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(
			_full_input.ebs,
			{"default_encryption_enabled": false},
		)},
	)
	some v in r
	v.check_id == "storage_ebs_default_encryption"
}

test_storage_02_compliant if {
	_violations_for("storage_ebs_default_encryption", _full_input) == 0
}

# =========================================================================
# storage_03 — EBS snapshot publicly shared
# =========================================================================
test_storage_03_alarm if {
	snap := object.union(_good_snap, {
		"create_volume_permissions": [{"group": "all"}],
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"snapshots": [snap]})},
	)
	some v in r
	v.check_id == "storage_ebs_snapshot_private"
}

test_storage_03_compliant if {
	_violations_for("storage_ebs_snapshot_private", _full_input) == 0
}

# =========================================================================
# storage_04 — EBS snapshot not encrypted
# =========================================================================
test_storage_04_alarm if {
	snap := object.union(_good_snap, {"encrypted": false})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"snapshots": [snap]})},
	)
	some v in r
	v.check_id == "storage_ebs_snapshot_encrypted"
}

test_storage_04_compliant if {
	_violations_for("storage_ebs_snapshot_encrypted", _full_input) == 0
}

test_storage_04_skip_other_account if {
	snap := object.union(_good_snap, {
		"encrypted": false,
		"owner_id": "999888777666",
	})
	_violations_for("storage_ebs_snapshot_encrypted", object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"snapshots": [snap]})},
	)) == 0
}

# =========================================================================
# storage_05 — Unattached volume > 30 days
# =========================================================================
test_storage_05_alarm if {
	vol := object.union(_good_vol, {
		"state": "available",
		"days_since_detached": 45,
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)
	some v in r
	v.check_id == "storage_ebs_unattached_review"
}

test_storage_05_compliant if {
	_violations_for("storage_ebs_unattached_review", _full_input) == 0
}

test_storage_05_compliant_under_30 if {
	vol := object.union(_good_vol, {
		"state": "available",
		"days_since_detached": 10,
	})
	_violations_for("storage_ebs_unattached_review", object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)) == 0
}

# =========================================================================
# storage_06 — Snapshot shared with unapproved account
# =========================================================================
test_storage_06_alarm if {
	snap := object.union(_good_snap, {
		"create_volume_permissions": [{"user_id": "111222333444"}],
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"snapshots": [snap]})},
	)
	some v in r
	v.check_id == "storage_ebs_snapshot_approved_accts"
}

test_storage_06_compliant if {
	_violations_for("storage_ebs_snapshot_approved_accts", _full_input) == 0
}

# =========================================================================
# storage_07 — No lifecycle policies
# =========================================================================
test_storage_07_alarm if {
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(
			_full_input.ebs,
			{"lifecycle_policies_count": 0},
		)},
	)
	some v in r
	v.check_id == "storage_ebs_snapshot_lifecycle"
}

test_storage_07_compliant if {
	_violations_for("storage_ebs_snapshot_lifecycle", _full_input) == 0
}

# =========================================================================
# storage_08 — Production volume uses magnetic type
# =========================================================================
test_storage_08_alarm if {
	vol := object.union(_good_vol, {"volume_type": "standard"})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)
	some v in r
	v.check_id == "storage_ebs_no_magnetic"
}

test_storage_08_compliant if {
	_violations_for("storage_ebs_no_magnetic", _full_input) == 0
}

test_storage_08_compliant_dev if {
	vol := object.union(
		object.remove(_good_vol, ["tags"]),
		{
			"volume_type": "standard",
			"tags": {"environment": "development"},
		},
	)
	_violations_for("storage_ebs_no_magnetic", object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)) == 0
}

# =========================================================================
# storage_09 — Sensitive volume uses AWS-managed key
# =========================================================================
test_storage_09_alarm if {
	vol := object.union(_good_vol, {
		"kms_key_id": "alias/aws/ebs",
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)
	some v in r
	v.check_id == "storage_ebs_kms_encryption"
}

test_storage_09_compliant if {
	_violations_for("storage_ebs_kms_encryption", _full_input) == 0
}

test_storage_09_compliant_not_sensitive if {
	vol := object.union(
		object.remove(_good_vol, ["tags"]),
		{
			"kms_key_id": "alias/aws/ebs",
			"tags": {
				"environment": "production",
				"data_classification": "public",
			},
		},
	)
	_violations_for("storage_ebs_kms_encryption", object.union(
		_full_input,
		{"ebs": object.union(_full_input.ebs, {"volumes": [vol]})},
	)) == 0
}

# =========================================================================
# storage_10 — EFS not encrypted at rest
# =========================================================================
test_storage_10_alarm if {
	fs := object.union(_good_efs, {"encrypted": false})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_encryption_rest"
}

test_storage_10_compliant if {
	_violations_for("storage_efs_encryption_rest", _full_input) == 0
}

# =========================================================================
# storage_11 — EFS no encryption in transit
# =========================================================================
test_storage_11_alarm if {
	fs := object.union(_good_efs, {
		"transit_encryption_enabled": false,
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_encryption_transit"
}

test_storage_11_compliant if {
	_violations_for("storage_efs_encryption_transit", _full_input) == 0
}

# =========================================================================
# storage_12 — EFS backup not enabled
# =========================================================================
test_storage_12_alarm if {
	fs := object.union(_good_efs, {
		"backup_policy": {"status": "DISABLED"},
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_backup"
}

test_storage_12_compliant if {
	_violations_for("storage_efs_backup", _full_input) == 0
}

# =========================================================================
# storage_13 — EFS public access
# =========================================================================
test_storage_13_alarm if {
	fs := object.union(_good_efs, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "elasticfilesystem:ClientMount",
		}]},
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_no_public_policy"
}

test_storage_13_compliant if {
	_violations_for("storage_efs_no_public_policy", _full_input) == 0
}

test_storage_13_compliant_with_condition if {
	fs := object.union(_good_efs, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "elasticfilesystem:ClientMount",
			"Condition": {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}},
		}]},
	})
	_violations_for("storage_efs_no_public_policy", object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)) == 0
}

# =========================================================================
# storage_14 — EFS access point no POSIX user
# =========================================================================
test_storage_14_alarm if {
	ap := object.remove(_good_ap, ["posix_user"])
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"access_points": [ap]})},
	)
	some v in r
	v.check_id == "storage_efs_access_point_enforcement"
}

test_storage_14_compliant if {
	_violations_for("storage_efs_access_point_enforcement", _full_input) == 0
}

# =========================================================================
# storage_15 — Sensitive EFS uses AWS-managed key
# =========================================================================
test_storage_15_alarm if {
	fs := object.union(_good_efs, {
		"kms_key_id": "alias/aws/elasticfilesystem",
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_kms_encryption"
}

test_storage_15_compliant if {
	_violations_for("storage_efs_kms_encryption", _full_input) == 0
}

test_storage_15_compliant_not_sensitive if {
	fs := object.union(
		object.remove(_good_efs, ["tags"]),
		{
			"kms_key_id": "alias/aws/elasticfilesystem",
			"tags": {
				"owner": "platform-team",
				"data_classification": "public",
				"data_criticality": "high",
				"environment": "production",
			},
		},
	)
	_violations_for("storage_efs_kms_encryption", object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)) == 0
}

# =========================================================================
# storage_16 — EFS mount target in public subnet
# =========================================================================
test_storage_16_alarm if {
	mt := object.union(_good_mt, {
		"subnet_map_public_ip": true,
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"mount_targets": [mt]})},
	)
	some v in r
	v.check_id == "storage_efs_private_subnets"
}

test_storage_16_compliant if {
	_violations_for("storage_efs_private_subnets", _full_input) == 0
}

# =========================================================================
# storage_17 — EFS no lifecycle policy
# =========================================================================
test_storage_17_alarm if {
	fs := object.remove(_good_efs, ["lifecycle_policies"])
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_lifecycle"
}

test_storage_17_compliant if {
	_violations_for("storage_efs_lifecycle", _full_input) == 0
}

# =========================================================================
# storage_18 — EFS missing owner tag
# =========================================================================
test_storage_18_alarm if {
	fs := object.union(
		object.remove(_good_efs, ["tags"]),
		{"tags": {
			"data_classification": "sensitive",
			"data_criticality": "high",
			"environment": "production",
		}},
	)
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_tags"
}

test_storage_18_compliant if {
	_violations_for("storage_efs_tags", _full_input) == 0
}

# =========================================================================
# storage_19 — Critical EFS no replication
# =========================================================================
test_storage_19_alarm if {
	fs := object.union(_good_efs, {
		"replication_configuration": {"destinations": []},
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_replication"
}

test_storage_19_compliant if {
	_violations_for("storage_efs_replication", _full_input) == 0
}

test_storage_19_compliant_low_criticality if {
	fs := object.union(
		object.remove(_good_efs, ["tags"]),
		{
			"replication_configuration": {"destinations": []},
			"tags": {
				"owner": "platform-team",
				"data_classification": "sensitive",
				"data_criticality": "low",
				"environment": "production",
			},
		},
	)
	_violations_for("storage_efs_replication", object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)) == 0
}

# =========================================================================
# storage_20 — Production EFS bursting mode with large IA data
# =========================================================================
test_storage_20_alarm if {
	fs := object.union(_good_efs, {
		"throughput_mode": "bursting",
		"size_in_bytes": {"value_in_ia": 2000000000},
	})
	r := storage.violations with input as object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)
	some v in r
	v.check_id == "storage_efs_throughput_mode"
}

test_storage_20_compliant if {
	_violations_for("storage_efs_throughput_mode", _full_input) == 0
}

test_storage_20_compliant_small_ia if {
	fs := object.union(_good_efs, {
		"throughput_mode": "bursting",
		"size_in_bytes": {"value_in_ia": 500000000},
	})
	_violations_for("storage_efs_throughput_mode", object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)) == 0
}

test_storage_20_compliant_dev if {
	fs := object.union(
		object.remove(_good_efs, ["tags"]),
		{
			"throughput_mode": "bursting",
			"size_in_bytes": {"value_in_ia": 2000000000},
			"tags": {
				"owner": "platform-team",
				"data_classification": "sensitive",
				"data_criticality": "high",
				"environment": "development",
			},
		},
	)
	_violations_for("storage_efs_throughput_mode", object.union(
		_full_input,
		{"efs": object.union(_full_input.efs, {"file_systems": [fs]})},
	)) == 0
}

# =========================================================================
# Error handlers
# =========================================================================
test_error_ebs_missing if {
	r := storage.error with input as {
		"efs": _full_input.efs,
	}
	some e in r
	e.check_id == "storage_ebs_error"
}

test_error_efs_missing if {
	r := storage.error with input as {
		"ebs": _full_input.ebs,
	}
	some e in r
	e.check_id == "storage_efs_error"
}
