"""API Gateway service collector.

Collects REST APIs, HTTP APIs, stages, and usage plans
to match the Rego policy expectations at
policies/network/api_gateway.rego.
"""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class APIGatewayCollector(BaseCollector):
    """Collects API Gateway REST APIs, HTTP APIs,
    stages, and usage plans."""

    def __init__(
        self, session, account_id="", region=""
    ):
        super().__init__(session)
        self._account_id = account_id
        self._region = region or (
            session.region_name or ""
        )

    def _get_account_id(self) -> str:
        """Return cached account_id, fetching via
        STS only once if not provided."""
        if not self._account_id:
            try:
                sts = self.session.client("sts")
                self._account_id = (
                    sts.get_caller_identity()[
                        "Account"
                    ]
                )
            except Exception as exc:
                logger.error(
                    "STS get_caller_identity: %s",
                    exc,
                )
                self._account_id = "unknown"
        return self._account_id

    # --------------------------------------------------
    # Public interface
    # --------------------------------------------------

    def collect(self) -> tuple[str, dict]:
        """Collect all API Gateway resources."""
        client = self.session.client("apigateway")
        apigw2 = self.session.client("apigatewayv2")
        waf = self._init_waf_client()

        rest_apis = self._get_rest_apis(client)
        stages = self._get_all_stages(
            client, rest_apis, waf
        )
        http_apis = self._get_http_apis(apigw2)
        usage_plans = self._get_usage_plans(client)

        return "apigateway", {
            "rest_apis": rest_apis + http_apis,
            "stages": stages,
            "usage_plans": usage_plans,
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        """Targeted collection for a single API."""
        client = self.session.client("apigateway")
        try:
            resp = client.get_rest_api(
                restApiId=resource_id
            )
            return self._build_rest_api(
                client, resp
            )
        except Exception:
            pass
        apigw2 = self.session.client("apigatewayv2")
        try:
            resp = apigw2.get_api(
                ApiId=resource_id
            )
            return self._build_http_api(resp)
        except Exception as exc:
            logger.error(
                "APIGateway get_api: %s", exc
            )
        return {}

    # --------------------------------------------------
    # WAFv2 helper
    # --------------------------------------------------

    def _init_waf_client(self):
        """Create WAFv2 client for web ACL lookups.
        Returns None on failure."""
        try:
            return self.session.client("wafv2")
        except Exception as exc:
            logger.warning(
                "WAFv2 client init failed: %s",
                exc,
            )
            return None

    def _get_web_acl_arn(self, waf, resource_arn):
        """Look up the WAF WebACL attached to a
        resource. Returns arn string or None."""
        if not waf or not resource_arn:
            return None
        try:
            resp = waf.get_web_acl_for_resource(
                ResourceArn=resource_arn
            )
            acl = resp.get("WebACL", {})
            return acl.get("ARN") or None
        except Exception:
            return None

    # --------------------------------------------------
    # REST APIs
    # --------------------------------------------------

    def _get_rest_apis(self, client) -> list[dict]:
        """Paginate through all REST APIs."""
        apis: list[dict] = []
        try:
            paginator = client.get_paginator(
                "get_rest_apis"
            )
            for page in paginator.paginate():
                for item in page.get("items", []):
                    apis.append(
                        self._build_rest_api(
                            client, item
                        )
                    )
        except Exception as exc:
            logger.error(
                "APIGateway get_rest_apis: %s", exc
            )
        return apis

    def _build_rest_api(
        self, client, item: dict
    ) -> dict:
        """Normalise a single REST API to the schema
        expected by Rego."""
        api_id = item.get("id", "")
        region = self._region
        acct = self._get_account_id()
        arn = (
            f"arn:aws:apigateway:{region}"
            f"::{acct}:/restapis/{api_id}"
        )

        ep_cfg = item.get(
            "endpointConfiguration", {}
        )
        endpoint_configuration = {
            "types": ep_cfg.get("types", []),
            "vpc_endpoint_ids": ep_cfg.get(
                "vpcEndpointIds", []
            ),
        }

        cors = self._get_cors_for_rest(
            client, api_id
        )

        validator_id = (
            self._get_first_request_validator(
                client, api_id
            )
        )

        compression = item.get(
            "minimumCompressionSize"
        )

        tls_raw = item.get(
            "mutualTlsAuthentication", {}
        )
        tls_config = {
            "insecure_skip_verification": bool(
                tls_raw.get(
                    "truststoreWarnings", []
                )
            ),
        }

        return {
            "id": api_id,
            "name": item.get("name", ""),
            "arn": arn,
            "tags": item.get("tags", {}),
            "endpoint_configuration": (
                endpoint_configuration
            ),
            "cors_configuration": cors,
            "request_validator_id": validator_id,
            "minimum_compression_size": compression,
            "tls_config": tls_config,
        }

    def _get_cors_for_rest(
        self, client, api_id: str
    ) -> dict:
        """Attempt to extract CORS origins from
        the gateway responses of a REST API."""
        allow_origins: list[str] = []
        try:
            resp = client.get_gateway_responses(
                restApiId=api_id
            )
            for gr in resp.get("items", []):
                params = gr.get(
                    "responseParameters", {}
                )
                hdr_key = (
                    "gatewayresponse.header"
                    ".Access-Control-Allow-Origin"
                )
                origin = params.get(hdr_key, "")
                if origin:
                    cleaned = origin.strip("'\"")
                    allow_origins.append(cleaned)
        except Exception:
            pass
        return {"allow_origins": allow_origins}

    def _get_first_request_validator(
        self, client, api_id: str
    ) -> str | None:
        """Return the ID of the first request
        validator, or None if none exist."""
        try:
            resp = client.get_request_validators(
                restApiId=api_id
            )
            items = resp.get("items", [])
            if items:
                return items[0].get("id")
        except Exception:
            pass
        return None

    # --------------------------------------------------
    # HTTP APIs (V2) — combined into rest_apis list
    # --------------------------------------------------

    def _get_http_apis(
        self, apigw2
    ) -> list[dict]:
        """Collect all V2 HTTP/WebSocket APIs."""
        apis: list[dict] = []
        try:
            resp = apigw2.get_apis()
            for item in resp.get("Items", []):
                apis.append(
                    self._build_http_api(item)
                )
        except Exception as exc:
            logger.error(
                "APIGatewayV2 get_apis: %s", exc
            )
        return apis

    def _build_http_api(
        self, item: dict
    ) -> dict:
        """Normalise a V2 HTTP API to the same
        shape as REST APIs."""
        api_id = item.get("ApiId", "")
        region = self._region
        acct = self._get_account_id()
        arn = (
            f"arn:aws:apigateway:{region}"
            f"::{acct}:/apis/{api_id}"
        )

        cors_raw = item.get("CorsConfiguration", {})
        allow_origins = cors_raw.get(
            "AllowOrigins", []
        )

        return {
            "id": api_id,
            "name": item.get("Name", ""),
            "arn": arn,
            "tags": item.get("Tags", {}),
            "endpoint_configuration": {
                "types": ["REGIONAL"],
                "vpc_endpoint_ids": [],
            },
            "cors_configuration": {
                "allow_origins": allow_origins,
            },
            "request_validator_id": None,
            "minimum_compression_size": None,
            "tls_config": {
                "insecure_skip_verification": (
                    False
                ),
            },
        }

    # --------------------------------------------------
    # Stages
    # --------------------------------------------------

    def _get_all_stages(
        self, client, rest_apis, waf
    ) -> list[dict]:
        """Iterate every REST API and collect its
        stages."""
        stages: list[dict] = []
        for api in rest_apis:
            api_id = api["id"]
            try:
                resp = client.get_stages(
                    restApiId=api_id
                )
                for s in resp.get("item", []):
                    stages.append(
                        self._build_stage(
                            api_id, s, waf
                        )
                    )
            except Exception as exc:
                logger.error(
                    "get_stages(%s): %s",
                    api_id,
                    exc,
                )
        return stages

    def _build_stage(
        self, api_id: str, item: dict, waf
    ) -> dict:
        """Normalise a single stage dict."""
        region = self._region
        stage_name = item.get("stageName", "")
        arn = (
            f"arn:aws:apigateway:{region}"
            f"::/restapis/{api_id}"
            f"/stages/{stage_name}"
        )

        # Access log settings
        log_raw = item.get(
            "accessLogSettings", {}
        )
        access_log_settings = {
            "destination_arn": (
                log_raw.get("destinationArn")
            ),
        }

        # Method settings → derive logging level
        # and throttle from the catch-all */*
        method_settings = item.get(
            "methodSettings", {}
        )
        wildcard = method_settings.get("*/*", {})
        logging_level = wildcard.get(
            "loggingLevel", "OFF"
        )
        throttle_rate = wildcard.get(
            "throttlingRateLimit", 0
        )
        default_route_settings = {
            "logging_level": logging_level,
            "throttling_rate_limit": int(
                throttle_rate
            ),
        }

        tags = item.get("tags", {})

        # WAF web ACL lookup
        web_acl_arn = self._get_web_acl_arn(
            waf, arn
        )

        client_cert = item.get(
            "clientCertificateId"
        )

        return {
            "rest_api_id": api_id,
            "stage_name": stage_name,
            "arn": arn,
            "access_log_settings": (
                access_log_settings
            ),
            "default_route_settings": (
                default_route_settings
            ),
            "tags": tags,
            "web_acl_arn": web_acl_arn,
            "client_certificate_id": client_cert,
        }

    # --------------------------------------------------
    # Usage Plans
    # --------------------------------------------------

    def _get_usage_plans(
        self, client
    ) -> list[dict]:
        """Paginate through all usage plans."""
        plans: list[dict] = []
        try:
            paginator = client.get_paginator(
                "get_usage_plans"
            )
            for page in paginator.paginate():
                for item in page.get(
                    "items", []
                ):
                    plans.append(
                        self._build_usage_plan(
                            item
                        )
                    )
        except Exception as exc:
            logger.error(
                "get_usage_plans: %s", exc
            )
        return plans

    def _build_usage_plan(
        self, item: dict
    ) -> dict:
        """Normalise a single usage plan."""
        throttle_raw = item.get("throttle", {})
        api_stages_raw = item.get(
            "apiStages", []
        )
        api_stages = [
            {
                "api_id": s.get("apiId", ""),
                "stage": s.get("stage", ""),
            }
            for s in api_stages_raw
        ]

        return {
            "id": item.get("id", ""),
            "tags": item.get("tags", {}),
            "api_stages": api_stages,
            "throttle": {
                "rate_limit": int(
                    throttle_raw.get(
                        "rateLimit", 0
                    )
                ),
            },
        }
