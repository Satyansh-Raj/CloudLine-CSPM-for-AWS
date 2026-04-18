"""Tests for OPA client factory."""

from app.engine.opa_cli import OPACLIClient
from app.engine.opa_client import create_opa_client
from app.engine.opa_http import OPAHTTPClient


class TestOPAClientFactory:
    def test_create_cli_client(self):
        """Test factory creates CLI client."""
        client = create_opa_client(mode="cli")
        assert isinstance(client, OPACLIClient)

    def test_create_http_client(self):
        """Test factory creates HTTP client."""
        client = create_opa_client(mode="http")
        assert isinstance(client, OPAHTTPClient)

    def test_default_mode_is_cli(self):
        """Test default mode is CLI."""
        client = create_opa_client()
        assert isinstance(client, OPACLIClient)

    def test_http_client_uses_url(self):
        """Test HTTP client gets custom URL."""
        url = "http://custom-opa:9999"
        client = create_opa_client(
            mode="http", opa_http_url=url
        )
        assert isinstance(client, OPAHTTPClient)
        assert client.base_url == url

    def test_cli_client_uses_binary(self):
        """Test CLI client gets custom binary."""
        client = create_opa_client(
            mode="cli",
            opa_binary="/opt/opa",
            policy_dir="/opt/policies",
        )
        assert isinstance(client, OPACLIClient)
        assert client.opa_binary == "/opt/opa"
