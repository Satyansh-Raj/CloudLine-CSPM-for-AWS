"""Tests for app config and dependencies."""

from pathlib import Path

from app.config import (
    Settings,
    _auto_generate_api_key,
    settings,
)
from app.dependencies import (
    get_boto3_session,
    get_settings,
)


class TestSettings:
    def test_defaults(self):
        s = Settings()
        assert s.aws_region  # set via .env or default
        assert s.app_env in (
            "development", "testing", "production",
        )
        assert s.scan_interval_minutes > 0
        assert s.log_level in (
            "DEBUG", "INFO", "WARNING", "ERROR",
        )

    def test_custom_values(self):
        s = Settings(
            aws_region="eu-west-1",
            app_env="testing",
            scan_interval_minutes=5,
        )
        assert s.aws_region == "eu-west-1"
        assert s.app_env == "testing"
        assert s.scan_interval_minutes == 5

    def test_singleton(self):
        assert settings is not None
        assert isinstance(settings, Settings)


class TestAutoGenerateApiKey:
    def _patch_env_path(self, monkeypatch, env_path):
        """Redirect _auto_generate_api_key to use
        a temp .env path."""
        original = Path.__truediv__

        def patched(self, other):
            if other == ".env":
                return env_path
            return original(self, other)

        monkeypatch.setattr(Path, "__truediv__", patched)

    def test_creates_env_file(
        self, tmp_path, monkeypatch
    ):
        env_path = tmp_path / ".env"
        self._patch_env_path(monkeypatch, env_path)
        key = _auto_generate_api_key()
        assert len(key) == 64
        assert env_path.exists()
        assert f"API_KEY={key}" in env_path.read_text()

    def test_updates_existing_env_file(
        self, tmp_path, monkeypatch
    ):
        env_path = tmp_path / ".env"
        env_path.write_text(
            "AWS_REGION=us-east-1\n"
            "API_KEY=\n"
            "OPA_MODE=cli\n"
        )
        self._patch_env_path(monkeypatch, env_path)
        key = _auto_generate_api_key()
        content = env_path.read_text()
        assert f"API_KEY={key}" in content
        assert "AWS_REGION=us-east-1" in content
        assert "OPA_MODE=cli" in content

    def test_appends_to_env_without_api_key(
        self, tmp_path, monkeypatch
    ):
        env_path = tmp_path / ".env"
        env_path.write_text("AWS_REGION=us-east-1\n")
        self._patch_env_path(monkeypatch, env_path)
        key = _auto_generate_api_key()
        content = env_path.read_text()
        assert f"API_KEY={key}" in content
        assert "AWS_REGION=us-east-1" in content


class TestDependencies:
    def test_get_settings(self):
        s = get_settings()
        assert isinstance(s, Settings)

    def test_get_boto3_session(self):
        session = get_boto3_session()
        assert session is not None
