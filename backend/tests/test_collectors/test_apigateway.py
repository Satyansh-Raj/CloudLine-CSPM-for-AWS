"""Tests for API Gateway collector using moto."""

import pytest

from app.collectors.apigateway import (
    APIGatewayCollector,
)


@pytest.fixture
def apigateway_setup(mock_session):
    """Set up REST API for testing."""
    client = mock_session.client("apigateway")
    client.create_rest_api(
        name="test-api",
        endpointConfiguration={
            "types": ["REGIONAL"],
        },
    )
    return mock_session


class TestAPIGatewayCollector:
    def test_collect_returns_apigateway_key(
        self, apigateway_setup
    ):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        key, _ = collector.collect()
        assert key == "apigateway"

    def test_collect_has_apis(
        self, apigateway_setup
    ):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        _, data = collector.collect()
        assert "apis" in data
        assert len(data["apis"]) >= 1

    def test_api_name(self, apigateway_setup):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        _, data = collector.collect()
        names = [
            a["name"] for a in data["apis"]
        ]
        assert "test-api" in names

    def test_api_has_endpoint_type(
        self, apigateway_setup
    ):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        _, data = collector.collect()
        api = next(
            a
            for a in data["apis"]
            if a["name"] == "test-api"
        )
        assert "endpoint_type" in api
        assert api["endpoint_type"] == "REGIONAL"

    def test_api_has_protocol_type(
        self, apigateway_setup
    ):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        _, data = collector.collect()
        api = next(
            a
            for a in data["apis"]
            if a["name"] == "test-api"
        )
        assert api["protocol_type"] == "REST"

    def test_collect_resource(
        self, apigateway_setup
    ):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        _, data = collector.collect()
        api_id = data["apis"][0]["api_id"]
        result = collector.collect_resource(
            api_id
        )
        assert result["name"] == "test-api"

    def test_collect_resource_not_found(
        self, apigateway_setup
    ):
        collector = APIGatewayCollector(
            apigateway_setup
        )
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}
