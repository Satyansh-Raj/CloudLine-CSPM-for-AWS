package aws.network.waf

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule waf_cloudfront_association — WAF WebACL must be associated with CloudFront distributions
# ---------------------------------------------------------------------------
violations contains result if {
	some dist in input.waf.cloudfront_distributions
	not dist.web_acl_id
	dist.tags.environment == "production"
	result := {
		"check_id": "waf_cloudfront_association",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production CloudFront distribution '%s' has no WAF WebACL associated",
			[dist.distribution_id],
		),
		"resource": dist.distribution_id,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_01",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_alb_association — WAF WebACL must be associated with ALBs
# ---------------------------------------------------------------------------
violations contains result if {
	some alb in input.waf.albs
	not alb.web_acl_arn
	alb.tags.environment == "production"
	result := {
		"check_id": "waf_alb_association",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production ALB '%s' has no WAF WebACL associated",
			[alb.load_balancer_arn],
		),
		"resource": alb.load_balancer_arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_02",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_managed_rules — AWS Managed Rules must be enabled in WebACLs
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	managed_rules := [r | some r in acl.rules; contains(r.name, "AWS-AWSManagedRules")]
	count(managed_rules) == 0
	result := {
		"check_id": "waf_managed_rules",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' has no AWS Managed Rules enabled",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_03",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_rate_based_rules — Rate-based rules must be configured in WebACLs
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	rate_rules := [r | some r in acl.rules; r.statement.rate_based_statement]
	count(rate_rules) == 0
	result := {
		"check_id": "waf_rate_based_rules",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' has no rate-based (DDoS) rules configured",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_04",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_sqli_protection — SQL injection protection must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	sqli_rules := [r | some r in acl.rules; r.statement.sqli_match_statement]
	sql_managed := [r |
		some r in acl.rules
		contains(r.name, "SQLi")
	]
	count(sqli_rules) == 0
	count(sql_managed) == 0
	result := {
		"check_id": "waf_sqli_protection",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"WAF WebACL '%s' has no SQL injection protection rules",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_05",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_xss_protection — XSS protection must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	xss_rules := [r | some r in acl.rules; r.statement.xss_match_statement]
	xss_managed := [r |
		some r in acl.rules
		contains(r.name, "XSS")
	]
	count(xss_rules) == 0
	count(xss_managed) == 0
	result := {
		"check_id": "waf_xss_protection",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' has no XSS protection rules",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_06",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_logging — WAF logging must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	not acl.logging_configuration.resource_arn
	result := {
		"check_id": "waf_logging",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' does not have logging enabled",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_07",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_ip_reputation — IP reputation managed rule group must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	rep_rules := [r |
		some r in acl.rules
		contains(r.name, "AWSManagedRulesAmazonIpReputationList")
	]
	count(rep_rules) == 0
	result := {
		"check_id": "waf_ip_reputation",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' does not use Amazon IP Reputation List",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_08",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_bot_control — Bot Control managed rule group should be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	bot_rules := [r |
		some r in acl.rules
		contains(r.name, "AWSManagedRulesBotControlRuleSet")
	]
	count(bot_rules) == 0
	acl.tags.environment == "production"
	result := {
		"check_id": "waf_bot_control",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production WAF WebACL '%s' does not have Bot Control enabled",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_09",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_no_count_critical — No critical rules must be in COUNT-only mode
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	some rule in acl.rules
	rule.override_action.count != null
	contains(lower(rule.name), "sqli")
	result := {
		"check_id": "waf_no_count_critical",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' SQLi rule '%s' is in COUNT mode — not blocking",
			[acl.name, rule.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_10",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_shield_advanced — AWS Shield Advanced must be enabled for critical resources
# ---------------------------------------------------------------------------
violations contains result if {
	input.waf.shield_advanced_subscription == false
	result := {
		"check_id": "waf_shield_advanced",
		"status": "alarm",
		"severity": "medium",
		"reason": "AWS Shield Advanced is not subscribed — DDoS protection is limited",
		"resource": concat("", ["arn:aws:shield::", input.account_id, ":subscription"]),
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_11",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_default_block_apis — WAF WebACL must have a default action of BLOCK for APIs
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	acl.tags.resource_type == "api"
	acl.default_action.allow != null
	result := {
		"check_id": "waf_default_block_apis",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"API WAF WebACL '%s' has default action ALLOW — should be BLOCK",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_12",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_known_bad_inputs — Known bad inputs managed rule group must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	bad_input_rules := [r |
		some r in acl.rules
		contains(r.name, "AWSManagedRulesKnownBadInputsRuleSet")
	]
	count(bad_input_rules) == 0
	result := {
		"check_id": "waf_known_bad_inputs",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"WAF WebACL '%s' does not use Known Bad Inputs rule set",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_13",
	}
}

# ---------------------------------------------------------------------------
# Rule waf_log_redaction — WAF log redaction must not filter out critical fields
# ---------------------------------------------------------------------------
violations contains result if {
	some acl in input.waf.web_acls
	acl.logging_configuration.resource_arn
	redacted := acl.logging_configuration.redacted_fields
	some field in redacted
	field.single_header.name == "authorization"
	result := {
		"check_id": "waf_log_redaction",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"WAF WebACL '%s' redacts Authorization header from logs",
			[acl.name],
		),
		"resource": acl.arn,
		"domain": "network",
		"service": "waf",
		"remediation_id": "REM_waf_14",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.waf
	result := {
		"check_id": "waf_error",
		"status": "error",
		"severity": "critical",
		"reason": "WAF data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
		"service": "waf",
	}
}
