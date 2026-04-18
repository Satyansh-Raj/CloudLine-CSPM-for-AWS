"""Tests for BaseCollector abstract class."""

import pytest

from app.collectors.base import BaseCollector


class ConcreteCollector(BaseCollector):
    """Concrete implementation for testing."""

    def collect(self):
        return "test", {"data": True}

    def collect_resource(self, resource_id):
        return {"id": resource_id}


class TestBaseCollector:
    def test_collect_returns_tuple(
        self, mock_session
    ):
        collector = ConcreteCollector(mock_session)
        key, data = collector.collect()
        assert key == "test"
        assert data == {"data": True}

    def test_collect_resource(self, mock_session):
        collector = ConcreteCollector(mock_session)
        result = collector.collect_resource("r-123")
        assert result == {"id": "r-123"}

    def test_safe_call_success(self, mock_session):
        collector = ConcreteCollector(mock_session)
        result = collector._safe_call(
            lambda: "ok"
        )
        assert result == "ok"

    def test_safe_call_error(self, mock_session):
        collector = ConcreteCollector(mock_session)

        def fail():
            raise ValueError("boom")

        result = collector._safe_call(fail)
        assert result is None

    def test_cannot_instantiate_abstract(
        self, mock_session
    ):
        with pytest.raises(TypeError):
            BaseCollector(mock_session)
