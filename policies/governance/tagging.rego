package aws.governance.tagging

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule ec2_tag_name_required — EC2 instances must have a Name tag
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	not inst.tags["Name"]
	result := {
		"check_id": "ec2_tag_name_required",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' is missing required 'Name' tag",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "governance",
		"service": "ec2",
		"remediation_id": "REM_gov_01",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_tag_environment_required — EC2 instances must have an Environment tag
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	not inst.tags["environment"]
	result := {
		"check_id": "ec2_tag_environment_required",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' is missing required 'environment' tag",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "governance",
		"service": "ec2",
		"remediation_id": "REM_gov_02",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_tag_owner_required — EC2 instances must have an Owner tag
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	not inst.tags["Owner"]
	result := {
		"check_id": "ec2_tag_owner_required",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' is missing required 'Owner' tag",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "governance",
		"service": "ec2",
		"remediation_id": "REM_gov_03",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_tag_project_required — EC2 instances must have a Project tag
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	not inst.tags["Project"]
	result := {
		"check_id": "ec2_tag_project_required",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' is missing required 'Project' tag",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "governance",
		"service": "ec2",
		"remediation_id": "REM_gov_04",
	}
}

# ---------------------------------------------------------------------------
# Rule ec2_tag_costcenter_required — EC2 instances must have a CostCenter tag
# ---------------------------------------------------------------------------
violations contains result if {
	some inst in input.ec2.instances
	not inst.tags["CostCenter"]
	result := {
		"check_id": "ec2_tag_costcenter_required",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EC2 instance '%s' is missing required 'CostCenter' tag",
			[inst.instance_id],
		),
		"resource": inst.arn,
		"domain": "governance",
		"service": "ec2",
		"remediation_id": "REM_gov_05",
	}
}
