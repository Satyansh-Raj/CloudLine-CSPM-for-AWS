package aws.network.api_gateway

import future.keywords.if
import future.keywords.in

# =============================================================================
# API GATEWAY & LOAD BALANCER POLICY
# Rule naming: apigw_01 … apigw_20
# =============================================================================

weak_tls_policies := {
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

# ---------------------------------------------------------------------------
# Rule apigw_access_logging — API Gateway: access logging must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some stage in input.apigateway.stages
	not stage.access_log_settings.destination_arn
	result := {
		"check_id": "apigw_access_logging",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"API Gateway stage '%s/%s' does not have access logging enabled",
			[stage.rest_api_id, stage.stage_name],
		),
		"resource": stage.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_01",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_execution_logging — API Gateway: execution logging must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some stage in input.apigateway.stages
	stage.default_route_settings.logging_level == "OFF"
	result := {
		"check_id": "apigw_execution_logging",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"API Gateway stage '%s/%s' execution logging is OFF",
			[stage.rest_api_id, stage.stage_name],
		),
		"resource": stage.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_02",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_tls_12 — API Gateway: TLS 1.2 minimum must be enforced
# ---------------------------------------------------------------------------
violations contains result if {
	some api in input.apigateway.rest_apis
	api.minimum_compression_size
	api.tags.enforce_tls == "true"
	api.tls_config.insecure_skip_verification == true
	result := {
		"check_id": "apigw_tls_12",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"API Gateway API '%s' has TLS verification disabled",
			[api.id],
		),
		"resource": api.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_03",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_waf_webacl — API Gateway: WAF WebACL must be associated
# ---------------------------------------------------------------------------
violations contains result if {
	some stage in input.apigateway.stages
	stage.tags.environment == "production"
	not stage.web_acl_arn
	result := {
		"check_id": "apigw_waf_webacl",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production API Gateway stage '%s/%s' has no WAF WebACL associated",
			[stage.rest_api_id, stage.stage_name],
		),
		"resource": stage.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_04",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_throttling — API Gateway: throttling must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	some stage in input.apigateway.stages
	stage.default_route_settings.throttling_rate_limit == 0
	stage.tags.environment == "production"
	result := {
		"check_id": "apigw_throttling",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production API Gateway stage '%s/%s' has no throttling configured",
			[stage.rest_api_id, stage.stage_name],
		),
		"resource": stage.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_05",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_vpc_endpoint — API Gateway: private APIs must use VPC endpoint
# ---------------------------------------------------------------------------
violations contains result if {
	some api in input.apigateway.rest_apis
	api.endpoint_configuration.types[_] == "PRIVATE"
	count(api.endpoint_configuration.vpc_endpoint_ids) == 0
	result := {
		"check_id": "apigw_vpc_endpoint",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Private API Gateway '%s' has no VPC endpoint configured",
			[api.id],
		),
		"resource": api.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_06",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_cors_wildcard — API Gateway: CORS must not allow all origins (*)
# ---------------------------------------------------------------------------
violations contains result if {
	some api in input.apigateway.rest_apis
	some cors in api.cors_configuration.allow_origins
	cors == "*"
	result := {
		"check_id": "apigw_cors_wildcard",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"API Gateway '%s' CORS configuration allows all origins (*)",
			[api.id],
		),
		"resource": api.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_07",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_api_keys_required — API Gateway: API keys must be required for usage plans
# ---------------------------------------------------------------------------
violations contains result if {
	some plan in input.apigateway.usage_plans
	count(plan.api_stages) > 0
	plan.tags.environment == "production"
	plan.throttle.rate_limit == 0
	result := {
		"check_id": "apigw_api_keys_required",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"API Gateway usage plan '%s' has no rate limit configured",
			[plan.id],
		),
		"resource": plan.id,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_08",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_request_validation — API Gateway: request validation must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some api in input.apigateway.rest_apis
	api.tags.environment == "production"
	not api.request_validator_id
	result := {
		"check_id": "apigw_request_validation",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production API Gateway '%s' has no request validation enabled",
			[api.id],
		),
		"resource": api.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_09",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_client_certificate — API Gateway: client certificate must be configured for backend
# ---------------------------------------------------------------------------
violations contains result if {
	some stage in input.apigateway.stages
	stage.tags.environment == "production"
	not stage.client_certificate_id
	result := {
		"check_id": "apigw_client_certificate",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production API Gateway stage '%s/%s' has no client certificate for backend",
			[stage.rest_api_id, stage.stage_name],
		),
		"resource": stage.arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_10",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_https_listener — Load Balancer: must have at least one HTTPS listener
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.type == "application"
	https_listeners := [l | some l in lb.listeners; l.protocol == "HTTPS"]
	count(https_listeners) == 0
	result := {
		"check_id": "apigw_lb_https_listener",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("ALB '%s' has no HTTPS listener configured", [lb.load_balancer_name]),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_11",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_tls_12 — Load Balancer: TLS policy must use TLS 1.2 or higher
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	some listener in lb.listeners
	listener.protocol == "HTTPS"
	listener.ssl_policy in weak_tls_policies
	result := {
		"check_id": "apigw_lb_tls_12",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"ALB '%s' listener uses weak TLS policy '%s'",
			[lb.load_balancer_name, listener.ssl_policy],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_12",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_access_logging — Load Balancer: access logging must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.attributes.access_logs_s3_enabled == false
	result := {
		"check_id": "apigw_lb_access_logging",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Load balancer '%s' does not have access logging enabled",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_13",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_deletion_protection — Load Balancer: deletion protection must be enabled for production
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.tags.environment == "production"
	lb.attributes.deletion_protection_enabled == false
	result := {
		"check_id": "apigw_lb_deletion_protection",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production load balancer '%s' has deletion protection disabled",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_14",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_http_redirect_https — Load Balancer: HTTP must redirect to HTTPS
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	some listener in lb.listeners
	listener.protocol == "HTTP"
	listener.default_actions[_].type != "redirect"
	result := {
		"check_id": "apigw_lb_http_redirect_https",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"ALB '%s' HTTP listener does not redirect to HTTPS",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_15",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_internal_not_public — Load Balancer: internal LBs must not be internet-facing
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.tags.exposure == "internal"
	lb.scheme == "internet-facing"
	result := {
		"check_id": "apigw_lb_internal_not_public",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Load balancer '%s' is tagged internal but is internet-facing",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_16",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_waf_webacl — Load Balancer: WAF WebACL must be associated with production ALBs
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.type == "application"
	lb.tags.environment == "production"
	not lb.web_acl_arn
	result := {
		"check_id": "apigw_lb_waf_webacl",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production ALB '%s' has no WAF WebACL associated",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_waf_02",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_cert_not_expired — Load Balancer: TLS certificate must not be expired
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	some listener in lb.listeners
	listener.protocol == "HTTPS"
	some cert in listener.certificates
	cert.days_until_expiry <= 0
	result := {
		"check_id": "apigw_lb_cert_not_expired",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"ALB '%s' HTTPS listener has an expired TLS certificate",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_18",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_drop_invalid_headers — Load Balancer: drop invalid HTTP headers must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.type == "application"
	lb.attributes.routing_http_drop_invalid_header_fields_enabled == false
	result := {
		"check_id": "apigw_lb_drop_invalid_headers",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"ALB '%s' does not drop invalid HTTP header fields",
			[lb.load_balancer_name],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_19",
	}
}

# ---------------------------------------------------------------------------
# Rule apigw_lb_multi_az — Load Balancer: must be deployed across at least 2 AZs
# ---------------------------------------------------------------------------
violations contains result if {
	some lb in input.elb.load_balancers
	lb.type == "application"
	count(lb.availability_zones) < 2
	result := {
		"check_id": "apigw_lb_multi_az",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"ALB '%s' is deployed in only %d availability zone(s)",
			[lb.load_balancer_name, count(lb.availability_zones)],
		),
		"resource": lb.load_balancer_arn,
		"domain": "network",
		"service": "api_gateway",
		"remediation_id": "REM_apigw_20",
	}
}

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
error contains result if {
	not input.apigateway
	result := {
		"check_id": "apigw_apigateway_error",
		"status": "error",
		"severity": "critical",
		"reason": "API Gateway data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
		"service": "api_gateway",
	}
}

error contains result if {
	not input.elb
	result := {
		"check_id": "apigw_elb_error",
		"status": "error",
		"severity": "critical",
		"reason": "ELB data missing from input — collector may have failed",
		"resource": "",
		"domain": "network",
		"service": "api_gateway",
	}
}
