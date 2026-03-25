"""Tests for OPA HTTP client."""

from unittest.mock import MagicMock, patch

import httpx

from app.engine.opa_http import OPAHTTPClient


class TestOPAHTTPClient:
    def setup_method(self):
        self.client = OPAHTTPClient(
            base_url="http://opa:9720"
        )

    @patch("app.engine.opa_http.httpx.post")
    def test_evaluate_success(self, mock_post):
        """Test successful HTTP evaluation."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "result": [
                    {
                        "check_id": "C01",
                        "status": "alarm",
                    }
                ]
            },
        )
        mock_post.return_value.raise_for_status = (
            MagicMock()
        )
        results = self.client.evaluate(
            {"test": True},
            "data.aws.identity.iam.violations",
        )
        assert len(results) == 1
        assert results[0]["check_id"] == "C01"

    @patch("app.engine.opa_http.httpx.post")
    def test_evaluate_timeout(self, mock_post):
        """Test HTTP timeout."""
        mock_post.side_effect = (
            httpx.TimeoutException("timeout")
        )
        results = self.client.evaluate(
            {}, "data.aws.test"
        )
        assert results == []

    @patch("app.engine.opa_http.httpx.post")
    def test_evaluate_http_error(self, mock_post):
        """Test HTTP error response."""
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "internal error"
        mock_post.return_value = resp
        resp.raise_for_status.side_effect = (
            httpx.HTTPStatusError(
                "500", request=MagicMock(), response=resp
            )
        )
        results = self.client.evaluate(
            {}, "data.aws.test"
        )
        assert results == []

    @patch("app.engine.opa_http.httpx.post")
    def test_evaluate_all_success(self, mock_post):
        """Test evaluate_all via HTTP."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "result": {
                    "iam": {
                        "violations": [{
                            "check_id": "iam_root_mfa",
                            "status": "alarm",
                        }],
                        "compliant": [],
                    }
                }
            },
        )
        mock_post.return_value.raise_for_status = (
            MagicMock()
        )
        results = self.client.evaluate_all(
            {"test": True}
        )
        assert "iam" in results
        assert len(
            results["iam"]["violations"]
        ) == 1

    @patch("app.engine.opa_http.httpx.post")
    def test_evaluate_all_timeout(self, mock_post):
        """Test evaluate_all HTTP timeout."""
        mock_post.side_effect = (
            httpx.TimeoutException("timeout")
        )
        results = self.client.evaluate_all({})
        assert results == {}

    def test_query_to_path(self):
        """Test Rego query to REST path conversion."""
        path = self.client._query_to_path(
            "data.aws.identity.iam.violations"
        )
        assert path == (
            "data/aws/identity/iam/violations"
        )

    def test_query_to_path_simple(self):
        """Test simple query conversion."""
        path = self.client._query_to_path(
            "data.aws"
        )
        assert path == "data/aws"
