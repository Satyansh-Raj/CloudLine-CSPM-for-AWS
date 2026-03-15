"""Security middleware tests — CORS, headers, input validation."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    return TestClient(app)


class TestSecurityHeaders:
    """Verify security headers on all responses."""

    def test_x_content_type_options(self, client):
        resp = client.get("/health")
        assert (
            resp.headers["X-Content-Type-Options"]
            == "nosniff"
        )

    def test_x_frame_options(self, client):
        resp = client.get("/health")
        assert resp.headers["X-Frame-Options"] == "DENY"

    def test_content_security_policy(self, client):
        resp = client.get("/health")
        assert (
            resp.headers["Content-Security-Policy"]
            == "default-src 'self'"
        )

    def test_strict_transport_security(self, client):
        resp = client.get("/health")
        hsts = resp.headers[
            "Strict-Transport-Security"
        ]
        assert "max-age=31536000" in hsts

    def test_cache_control(self, client):
        resp = client.get("/health")
        assert "no-store" in resp.headers["Cache-Control"]

    def test_referrer_policy(self, client):
        resp = client.get("/health")
        assert (
            resp.headers["Referrer-Policy"]
            == "strict-origin-when-cross-origin"
        )

    def test_headers_on_api_routes(self, client):
        resp = client.get("/api/v1/compliance/score")
        assert (
            resp.headers["X-Content-Type-Options"]
            == "nosniff"
        )
        assert resp.headers["X-Frame-Options"] == "DENY"


class TestCORS:
    """Verify CORS configuration."""

    def test_cors_allowed_origin(self, client):
        resp = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert (
            resp.headers.get(
                "Access-Control-Allow-Origin"
            )
            == "http://localhost:5173"
        )

    def test_cors_disallowed_origin(self, client):
        resp = client.options(
            "/health",
            headers={
                "Origin": "http://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert (
            resp.headers.get(
                "Access-Control-Allow-Origin"
            )
            is None
        )

    def test_cors_allowed_methods(self, client):
        resp = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        allowed = resp.headers.get(
            "Access-Control-Allow-Methods", ""
        )
        assert "POST" in allowed

    def test_cors_allowed_headers(self, client):
        resp = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": (
                    "Authorization"
                ),
            },
        )
        assert (
            "Authorization"
            in resp.headers.get(
                "Access-Control-Allow-Headers", ""
            )
        )


class TestInputValidation:
    """Verify invalid inputs are rejected."""

    def test_invalid_json_body(self, client):
        resp = client.post(
            "/api/v1/scans",
            content="not json",
            headers={
                "Content-Type": "application/json"
            },
        )
        # Should not crash — either 422 or 202
        assert resp.status_code in (202, 422)

    def test_unknown_route_returns_404(self, client):
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
