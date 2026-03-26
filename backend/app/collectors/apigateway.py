"""API Gateway service collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class APIGatewayCollector(BaseCollector):
    """Collects API Gateway REST and HTTP APIs."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("apigateway")
        apigw2 = self.session.client("apigatewayv2")
        return "apigateway", {
            "apis": (
                self._get_rest_apis(client)
                + self._get_http_apis(apigw2)
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("apigateway")
        try:
            resp = client.get_rest_api(
                restApiId=resource_id
            )
            return self._build_rest_api(resp)
        except Exception:
            pass
        apigw2 = self.session.client("apigatewayv2")
        try:
            resp = apigw2.get_api(ApiId=resource_id)
            return self._build_http_api(resp)
        except Exception as e:
            logger.error(
                "APIGateway get_api: %s", e
            )
        return {}

    def _get_rest_apis(
        self, client
    ) -> list[dict]:
        apis = []
        try:
            resp = client.get_rest_apis()
            for item in resp.get("items", []):
                apis.append(
                    self._build_rest_api(item)
                )
        except Exception as e:
            logger.error(
                "APIGateway get_rest_apis: %s", e
            )
        return apis

    def _get_http_apis(
        self, apigw2
    ) -> list[dict]:
        apis = []
        try:
            resp = apigw2.get_apis()
            for item in resp.get("Items", []):
                apis.append(
                    self._build_http_api(item)
                )
        except Exception as e:
            logger.error(
                "APIGatewayV2 get_apis: %s", e
            )
        return apis

    def _build_rest_api(
        self, item: dict
    ) -> dict:
        endpoint_cfg = item.get(
            "endpointConfiguration", {}
        )
        types = endpoint_cfg.get("types", [])
        endpoint_type = (
            types[0] if types else "REGIONAL"
        )
        tags = item.get("tags", {})
        return {
            "api_id": item.get("id", ""),
            "name": item.get("name", ""),
            "arn": "",
            "endpoint_type": endpoint_type,
            "protocol_type": "REST",
            "tags": tags,
        }

    def _build_http_api(
        self, item: dict
    ) -> dict:
        tags = item.get("Tags", {})
        return {
            "api_id": item.get("ApiId", ""),
            "name": item.get("Name", ""),
            "arn": "",
            "endpoint_type": "REGIONAL",
            "protocol_type": item.get(
                "ProtocolType", "HTTP"
            ),
            "tags": tags,
        }
