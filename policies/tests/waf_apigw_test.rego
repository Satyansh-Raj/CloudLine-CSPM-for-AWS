package aws.network.waf_apigw_test

import data.aws.network.waf
import data.aws.network.api_gateway

# =========================================================================
# Helpers
# =========================================================================
_waf_for(check_id, inp) := count([v |
	some v in waf.violations with input as inp
	v.check_id == check_id
])

_apigw_for(check_id, inp) := count([v |
	some v in api_gateway.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# WAF — Minimal compliant fixtures
# =========================================================================
_good_cf_dist := {
	"distribution_id": "E123ABC",
	"web_acl_id": "arn:aws:wafv2::123456789012:global/webacl/my-acl/abc",
	"tags": {"environment": "production"},
}

_good_alb := {
	"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc",
	"web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc",
	"tags": {"environment": "production"},
}

_good_web_acl := {
	"name": "my-acl",
	"arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc",
	"default_action": {"block": {}},
	"rules": [
		{"name": "AWS-AWSManagedRulesCommonRuleSet", "statement": {}},
		{"name": "AWS-AWSManagedRulesSQLiRuleSet", "statement": {"sqli_match_statement": true}},
		{"name": "AWS-AWSManagedRulesXSSRuleSet", "statement": {"xss_match_statement": true}},
		{"name": "RateLimit", "statement": {"rate_based_statement": {"limit": 2000}}},
		{"name": "AWSManagedRulesAmazonIpReputationList", "statement": {}},
		{"name": "AWSManagedRulesBotControlRuleSet", "statement": {}},
		{"name": "AWSManagedRulesKnownBadInputsRuleSet", "statement": {}},
	],
	"logging_configuration": {
		"resource_arn": "arn:aws:s3:::my-waf-logs",
		"redacted_fields": [],
	},
	"tags": {
		"environment": "production",
		"resource_type": "web",
	},
}

_waf_input := {
	"waf": {
		"cloudfront_distributions": [_good_cf_dist],
		"albs": [_good_alb],
		"web_acls": [_good_web_acl],
		"shield_advanced_subscription": true,
	},
	"account_id": "123456789012",
}

# =========================================================================
# API Gateway — Minimal compliant fixtures
# =========================================================================
_good_stage := {
	"rest_api_id": "api-abc",
	"stage_name": "prod",
	"arn": "arn:aws:apigateway:us-east-1::/restapis/api-abc/stages/prod",
	"access_log_settings": {
		"destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/my-api",
	},
	"default_route_settings": {
		"logging_level": "INFO",
		"throttling_rate_limit": 1000,
	},
	"web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc",
	"client_certificate_id": "cert-abc123",
	"tags": {"environment": "production"},
}

_good_api := {
	"id": "api-abc",
	"arn": "arn:aws:apigateway:us-east-1::/restapis/api-abc",
	"minimum_compression_size": 1024,
	"tls_config": {"insecure_skip_verification": false},
	"endpoint_configuration": {
		"types": ["REGIONAL"],
		"vpc_endpoint_ids": [],
	},
	"cors_configuration": {"allow_origins": ["https://example.com"]},
	"request_validator_id": "rv-abc123",
	"tags": {"environment": "production", "enforce_tls": "true"},
}

_good_usage_plan := {
	"id": "plan-abc",
	"api_stages": [{"api_id": "api-abc", "stage": "prod"}],
	"throttle": {"rate_limit": 1000},
	"tags": {"environment": "production"},
}

_good_lb := {
	"load_balancer_name": "my-alb",
	"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc",
	"type": "application",
	"scheme": "internet-facing",
	"web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc",
	"listeners": [
		{
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
			"certificates": [{"days_until_expiry": 90}],
			"default_actions": [{"type": "forward"}],
		},
		{
			"protocol": "HTTP",
			"default_actions": [{"type": "redirect"}],
		},
	],
	"attributes": {
		"access_logs_s3_enabled": true,
		"deletion_protection_enabled": true,
		"routing_http_drop_invalid_header_fields_enabled": true,
	},
	"availability_zones": ["us-east-1a", "us-east-1b"],
	"tags": {"environment": "production", "exposure": "public"},
}

_apigw_input := {
	"apigateway": {
		"stages": [_good_stage],
		"rest_apis": [_good_api],
		"usage_plans": [_good_usage_plan],
	},
	"elb": {"load_balancers": [_good_lb]},
}

# =========================================================================
# waf_01 — CloudFront no WebACL
# =========================================================================
test_waf_01_alarm if {
	dist := object.remove(_good_cf_dist, ["web_acl_id"])
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"cloudfront_distributions": [dist]})},
	)
	some v in r
	v.check_id == "waf_cloudfront_association"
}

test_waf_01_compliant if {
	_waf_for("waf_cloudfront_association", _waf_input) == 0
}

# =========================================================================
# waf_02 — ALB no WebACL
# =========================================================================
test_waf_02_alarm if {
	alb := object.remove(_good_alb, ["web_acl_arn"])
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"albs": [alb]})},
	)
	some v in r
	v.check_id == "waf_alb_association"
}

test_waf_02_compliant if {
	_waf_for("waf_alb_association", _waf_input) == 0
}

# =========================================================================
# waf_03 — No AWS Managed Rules
# =========================================================================
test_waf_03_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [{"name": "custom-rule", "statement": {}}],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_managed_rules"
}

test_waf_03_compliant if {
	_waf_for("waf_managed_rules", _waf_input) == 0
}

# =========================================================================
# waf_04 — No rate-based rules
# =========================================================================
test_waf_04_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [{"name": "AWS-AWSManagedRulesCommonRuleSet", "statement": {}}],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_rate_based_rules"
}

test_waf_04_compliant if {
	_waf_for("waf_rate_based_rules", _waf_input) == 0
}

# =========================================================================
# waf_05 — No SQLi protection
# =========================================================================
test_waf_05_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [
			{"name": "RateLimit", "statement": {"rate_based_statement": {"limit": 2000}}},
		],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_sqli_protection"
}

test_waf_05_compliant if {
	_waf_for("waf_sqli_protection", _waf_input) == 0
}

# =========================================================================
# waf_06 — No XSS protection
# =========================================================================
test_waf_06_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [
			{"name": "RateLimit", "statement": {"rate_based_statement": {"limit": 2000}}},
		],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_xss_protection"
}

test_waf_06_compliant if {
	_waf_for("waf_xss_protection", _waf_input) == 0
}

# =========================================================================
# waf_07 — Logging not enabled
# =========================================================================
test_waf_07_alarm if {
	acl := object.union(
		object.remove(_good_web_acl, ["logging_configuration"]),
		{"logging_configuration": {}},
	)
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_logging"
}

test_waf_07_compliant if {
	_waf_for("waf_logging", _waf_input) == 0
}

# =========================================================================
# waf_08 — No IP Reputation List
# =========================================================================
test_waf_08_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [{"name": "custom", "statement": {}}],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_ip_reputation"
}

test_waf_08_compliant if {
	_waf_for("waf_ip_reputation", _waf_input) == 0
}

# =========================================================================
# waf_09 — No Bot Control (production)
# =========================================================================
test_waf_09_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [{"name": "custom", "statement": {}}],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_bot_control"
}

test_waf_09_compliant if {
	_waf_for("waf_bot_control", _waf_input) == 0
}

# =========================================================================
# waf_10 — SQLi rule in COUNT mode
# =========================================================================
test_waf_10_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [
			{"name": "AWS-SQLi-Protection", "statement": {}, "override_action": {"count": true}},
		],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_no_count_critical"
}

test_waf_10_compliant if {
	_waf_for("waf_no_count_critical", _waf_input) == 0
}

# =========================================================================
# waf_11 — Shield Advanced not subscribed
# =========================================================================
test_waf_11_alarm if {
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(
			_waf_input.waf,
			{"shield_advanced_subscription": false},
		)},
	)
	some v in r
	v.check_id == "waf_shield_advanced"
}

test_waf_11_compliant if {
	_waf_for("waf_shield_advanced", _waf_input) == 0
}

# =========================================================================
# waf_12 — API WebACL default action ALLOW
# =========================================================================
test_waf_12_alarm if {
	acl := object.union(
		object.remove(_good_web_acl, ["tags"]),
		{
			"default_action": {"allow": {}},
			"tags": {"environment": "production", "resource_type": "api"},
		},
	)
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_default_block_apis"
}

test_waf_12_compliant if {
	_waf_for("waf_default_block_apis", _waf_input) == 0
}

# =========================================================================
# waf_13 — No Known Bad Inputs rule set
# =========================================================================
test_waf_13_alarm if {
	acl := object.union(_good_web_acl, {
		"rules": [{"name": "custom", "statement": {}}],
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_known_bad_inputs"
}

test_waf_13_compliant if {
	_waf_for("waf_known_bad_inputs", _waf_input) == 0
}

# =========================================================================
# waf_14 — Log redaction of authorization header
# =========================================================================
test_waf_14_alarm if {
	acl := object.union(_good_web_acl, {
		"logging_configuration": {
			"resource_arn": "arn:aws:s3:::my-waf-logs",
			"redacted_fields": [{"single_header": {"name": "authorization"}}],
		},
	})
	r := waf.violations with input as object.union(
		_waf_input,
		{"waf": object.union(_waf_input.waf, {"web_acls": [acl]})},
	)
	some v in r
	v.check_id == "waf_log_redaction"
}

test_waf_14_compliant if {
	_waf_for("waf_log_redaction", _waf_input) == 0
}

# =========================================================================
# WAF error handler
# =========================================================================
test_waf_error_missing if {
	r := waf.error with input as {}
	some e in r
	e.check_id == "waf_error"
}

# =========================================================================
# apigw_01 — No access logging
# =========================================================================
test_apigw_01_alarm if {
	stage := object.remove(_good_stage, ["access_log_settings"])
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"stages": [stage]})},
	)
	some v in r
	v.check_id == "apigw_access_logging"
}

test_apigw_01_compliant if {
	_apigw_for("apigw_access_logging", _apigw_input) == 0
}

# =========================================================================
# apigw_02 — Execution logging OFF
# =========================================================================
test_apigw_02_alarm if {
	stage := object.union(_good_stage, {
		"default_route_settings": object.union(
			_good_stage.default_route_settings,
			{"logging_level": "OFF"},
		),
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"stages": [stage]})},
	)
	some v in r
	v.check_id == "apigw_execution_logging"
}

test_apigw_02_compliant if {
	_apigw_for("apigw_execution_logging", _apigw_input) == 0
}

# =========================================================================
# apigw_03 — TLS verification disabled
# =========================================================================
test_apigw_03_alarm if {
	api := object.union(_good_api, {
		"tls_config": {"insecure_skip_verification": true},
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"rest_apis": [api]})},
	)
	some v in r
	v.check_id == "apigw_tls_12"
}

test_apigw_03_compliant if {
	_apigw_for("apigw_tls_12", _apigw_input) == 0
}

# =========================================================================
# apigw_04 — Production stage no WAF
# =========================================================================
test_apigw_04_alarm if {
	stage := object.remove(_good_stage, ["web_acl_arn"])
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"stages": [stage]})},
	)
	some v in r
	v.check_id == "apigw_waf_webacl"
}

test_apigw_04_compliant if {
	_apigw_for("apigw_waf_webacl", _apigw_input) == 0
}

# =========================================================================
# apigw_05 — No throttling (production)
# =========================================================================
test_apigw_05_alarm if {
	stage := object.union(_good_stage, {
		"default_route_settings": object.union(
			_good_stage.default_route_settings,
			{"throttling_rate_limit": 0},
		),
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"stages": [stage]})},
	)
	some v in r
	v.check_id == "apigw_throttling"
}

test_apigw_05_compliant if {
	_apigw_for("apigw_throttling", _apigw_input) == 0
}

# =========================================================================
# apigw_06 — Private API no VPC endpoint
# =========================================================================
test_apigw_06_alarm if {
	api := object.union(_good_api, {
		"endpoint_configuration": {
			"types": ["PRIVATE"],
			"vpc_endpoint_ids": [],
		},
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"rest_apis": [api]})},
	)
	some v in r
	v.check_id == "apigw_vpc_endpoint"
}

test_apigw_06_compliant if {
	_apigw_for("apigw_vpc_endpoint", _apigw_input) == 0
}

# =========================================================================
# apigw_07 — CORS allows wildcard
# =========================================================================
test_apigw_07_alarm if {
	api := object.union(_good_api, {
		"cors_configuration": {"allow_origins": ["*"]},
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"rest_apis": [api]})},
	)
	some v in r
	v.check_id == "apigw_cors_wildcard"
}

test_apigw_07_compliant if {
	_apigw_for("apigw_cors_wildcard", _apigw_input) == 0
}

# =========================================================================
# apigw_08 — Usage plan no rate limit
# =========================================================================
test_apigw_08_alarm if {
	plan := object.union(_good_usage_plan, {
		"throttle": {"rate_limit": 0},
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"usage_plans": [plan]})},
	)
	some v in r
	v.check_id == "apigw_api_keys_required"
}

test_apigw_08_compliant if {
	_apigw_for("apigw_api_keys_required", _apigw_input) == 0
}

# =========================================================================
# apigw_09 — No request validation
# =========================================================================
test_apigw_09_alarm if {
	api := object.remove(_good_api, ["request_validator_id"])
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"rest_apis": [api]})},
	)
	some v in r
	v.check_id == "apigw_request_validation"
}

test_apigw_09_compliant if {
	_apigw_for("apigw_request_validation", _apigw_input) == 0
}

# =========================================================================
# apigw_10 — No client certificate
# =========================================================================
test_apigw_10_alarm if {
	stage := object.remove(_good_stage, ["client_certificate_id"])
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"apigateway": object.union(_apigw_input.apigateway, {"stages": [stage]})},
	)
	some v in r
	v.check_id == "apigw_client_certificate"
}

test_apigw_10_compliant if {
	_apigw_for("apigw_client_certificate", _apigw_input) == 0
}

# =========================================================================
# apigw_11 — ALB no HTTPS listener
# =========================================================================
test_apigw_11_alarm if {
	lb := object.union(_good_lb, {
		"listeners": [{"protocol": "HTTP", "default_actions": [{"type": "forward"}]}],
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_https_listener"
}

test_apigw_11_compliant if {
	_apigw_for("apigw_lb_https_listener", _apigw_input) == 0
}

# =========================================================================
# apigw_12 — Weak TLS policy
# =========================================================================
test_apigw_12_alarm if {
	lb := object.union(_good_lb, {
		"listeners": [{
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS-1-0-2015-04",
			"certificates": [{"days_until_expiry": 90}],
			"default_actions": [{"type": "forward"}],
		}],
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_tls_12"
}

test_apigw_12_compliant if {
	_apigw_for("apigw_lb_tls_12", _apigw_input) == 0
}

# =========================================================================
# apigw_13 — LB access logging disabled
# =========================================================================
test_apigw_13_alarm if {
	lb := object.union(_good_lb, {
		"attributes": object.union(
			_good_lb.attributes,
			{"access_logs_s3_enabled": false},
		),
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_access_logging"
}

test_apigw_13_compliant if {
	_apigw_for("apigw_lb_access_logging", _apigw_input) == 0
}

# =========================================================================
# apigw_14 — LB deletion protection disabled (production)
# =========================================================================
test_apigw_14_alarm if {
	lb := object.union(_good_lb, {
		"attributes": object.union(
			_good_lb.attributes,
			{"deletion_protection_enabled": false},
		),
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_deletion_protection"
}

test_apigw_14_compliant if {
	_apigw_for("apigw_lb_deletion_protection", _apigw_input) == 0
}

# =========================================================================
# apigw_15 — HTTP listener does not redirect
# =========================================================================
test_apigw_15_alarm if {
	lb := object.union(_good_lb, {
		"listeners": [{
			"protocol": "HTTP",
			"default_actions": [{"type": "forward"}],
		}],
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_http_redirect_https"
}

test_apigw_15_compliant if {
	_apigw_for("apigw_lb_http_redirect_https", _apigw_input) == 0
}

# =========================================================================
# apigw_16 — Internal LB is internet-facing
# =========================================================================
test_apigw_16_alarm if {
	lb := object.union(
		object.remove(_good_lb, ["tags"]),
		{"tags": {"environment": "production", "exposure": "internal"}},
	)
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_internal_not_public"
}

test_apigw_16_compliant if {
	_apigw_for("apigw_lb_internal_not_public", _apigw_input) == 0
}

# =========================================================================
# apigw_17 — Production ALB no WAF
# =========================================================================
test_apigw_17_alarm if {
	lb := object.remove(_good_lb, ["web_acl_arn"])
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_waf_webacl"
}

test_apigw_17_compliant if {
	_apigw_for("apigw_lb_waf_webacl", _apigw_input) == 0
}

# =========================================================================
# apigw_18 — Expired TLS certificate
# =========================================================================
test_apigw_18_alarm if {
	lb := object.union(_good_lb, {
		"listeners": [{
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
			"certificates": [{"days_until_expiry": -5}],
			"default_actions": [{"type": "forward"}],
		}],
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_cert_not_expired"
}

test_apigw_18_compliant if {
	_apigw_for("apigw_lb_cert_not_expired", _apigw_input) == 0
}

# =========================================================================
# apigw_19 — Drop invalid headers disabled
# =========================================================================
test_apigw_19_alarm if {
	lb := object.union(_good_lb, {
		"attributes": object.union(
			_good_lb.attributes,
			{"routing_http_drop_invalid_header_fields_enabled": false},
		),
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_drop_invalid_headers"
}

test_apigw_19_compliant if {
	_apigw_for("apigw_lb_drop_invalid_headers", _apigw_input) == 0
}

# =========================================================================
# apigw_20 — ALB < 2 AZs
# =========================================================================
test_apigw_20_alarm if {
	lb := object.union(_good_lb, {
		"availability_zones": ["us-east-1a"],
	})
	r := api_gateway.violations with input as object.union(
		_apigw_input,
		{"elb": {"load_balancers": [lb]}},
	)
	some v in r
	v.check_id == "apigw_lb_multi_az"
}

test_apigw_20_compliant if {
	_apigw_for("apigw_lb_multi_az", _apigw_input) == 0
}

# =========================================================================
# API Gateway error handlers
# =========================================================================
test_apigw_error_apigateway_missing if {
	r := api_gateway.error with input as {
		"elb": _apigw_input.elb,
	}
	some e in r
	e.check_id == "apigw_apigateway_error"
}

test_apigw_error_elb_missing if {
	r := api_gateway.error with input as {
		"apigateway": _apigw_input.apigateway,
	}
	some e in r
	e.check_id == "apigw_elb_error"
}
