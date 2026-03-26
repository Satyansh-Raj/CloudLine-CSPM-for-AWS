"""Verify Security Graph feature is fully removed."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestSecurityGraphRemoved:
    """The /inventory/graph endpoint must not exist."""

    def test_endpoint_returns_404(self):
        resp = client.get("/api/v1/inventory/graph")
        assert resp.status_code == 404

    def test_no_security_graph_router_import(self):
        """main.py must not import security_graph."""
        import inspect
        import app.main as m

        src = inspect.getsource(m)
        assert "security_graph" not in src

    def test_graph_module_deleted(self):
        """app.graph package must not exist."""
        try:
            import app.graph  # noqa: F401

            assert False, "app.graph still importable"
        except ImportError:
            pass
