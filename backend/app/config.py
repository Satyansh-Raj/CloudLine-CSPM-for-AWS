"""Application configuration via environment variables."""

import logging
import os
import secrets
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, EnvSettingsSource

logger = logging.getLogger(__name__)


class _RegionEnvSource(EnvSettingsSource):
    """Custom env source that parses AWS_REGIONS as a
    comma-separated string (e.g. us-east-1,eu-west-1)
    in addition to the standard JSON list format.

    Also falls back to AWS_REGION (singular) for
    backward compatibility with older .env files.
    """

    def prepare_field_value(
        self,
        field_name: str,
        field,
        value: object,
        value_is_complex: bool,
    ) -> object:
        if field_name == "aws_regions":
            # Fallback: AWS_REGION (singular) → list
            if value is None:
                single = os.environ.get("AWS_REGION")
                if single and single.strip():
                    return [single.strip()]
            if isinstance(value, str):
                stripped = value.strip()
                # JSON array — let parent handle it.
                if stripped.startswith("["):
                    return super().prepare_field_value(
                        field_name,
                        field,
                        value,
                        value_is_complex,
                    )
                # Comma-separated string.
                return [
                    r.strip()
                    for r in stripped.split(",")
                    if r.strip()
                ]
        return super().prepare_field_value(
            field_name, field, value, value_is_complex
        )


class Settings(BaseSettings):
    """Application settings loaded from env vars / .env."""

    # AWS — multi-region support.
    # aws_regions is the canonical field.
    # aws_region is a computed property that returns
    # the first element (backward compat).
    aws_regions: list[str] = ["us-east-1"]
    aws_account_id: str = ""

    @model_validator(mode="before")
    @classmethod
    def _coerce_aws_region(
        cls, values: object
    ) -> object:
        """If caller passes aws_region=X (old style),
        convert it to aws_regions=[X] so existing code
        and tests keep working without changes."""
        if not isinstance(values, dict):
            return values
        if (
            "aws_region" in values
            and "aws_regions" not in values
        ):
            values = dict(values)
            values["aws_regions"] = [
                values.pop("aws_region")
            ]
        return values

    @property
    def aws_region(self) -> str:
        """First region — backward compatibility."""
        return self.aws_regions[0]

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        """Replace the default env source with our custom
        one that handles comma-separated AWS_REGIONS."""
        return (
            init_settings,
            _RegionEnvSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )

    # Legacy API key (kept for backward compat)
    api_key: str = "change-me-in-env"

    # JWT Authentication
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7
    auth_enabled: bool = True

    # User management
    dynamodb_users_table: str = "cloudline-users"
    admin_bootstrap_email: str = ""
    admin_bootstrap_password: str = ""

    # OPA — mode selects CLI (local) vs HTTP (Docker)
    opa_mode: str = "cli"
    opa_binary_path: str = "opa"
    opa_policy_dir: str = "../policies"
    opa_http_url: str = "http://localhost:9720"

    # DynamoDB
    dynamodb_endpoint: str | None = None
    dynamodb_state_table: str = "violation-state"
    dynamodb_trends_table: str = (
        "compliance-trends"
    )
    dynamodb_correlation_table: str = (
        "event-correlation"
    )
    dynamodb_inventory_table: str = (
        "resource-inventory"
    )
    dynamodb_accounts_table: str = "target-accounts"
    dynamodb_macie_table: str = "macie-findings"
    # SNS (gracefully skips when empty)
    sns_alert_topic_arn: str = ""

    # WebSocket
    ws_heartbeat_interval: int = 30
    ws_max_connections: int = 100

    # CORS
    cors_origins: str = "http://localhost:5173"

    # Rate limiting
    rate_limit: str = "60/minute"

    # Jira integration
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""

    # App
    app_version: str = "0.1.0"
    app_env: str = "development"
    log_level: str = "DEBUG"
    scan_interval_minutes: int = 15
    correlation_window_minutes: int = 5
    model_config = {
        "env_file": ".env",
        "extra": "ignore",
    }


def _auto_generate_api_key() -> str:
    """Generate a secure API key, save it to .env,
    and return it.

    Called on first startup when no API_KEY is
    configured. The key is persisted so subsequent
    restarts reuse the same key.
    """
    key = secrets.token_hex(32)
    env_path = Path(__file__).resolve().parent.parent / ".env"

    if env_path.exists():
        content = env_path.read_text()
        # Replace placeholder or empty API_KEY line
        if "API_KEY=" in content:
            lines = content.splitlines()
            lines = [
                f"API_KEY={key}"
                if line.startswith("API_KEY=")
                else line
                for line in lines
            ]
            env_path.write_text(
                "\n".join(lines) + "\n"
            )
        else:
            with open(env_path, "a") as f:
                f.write(f"API_KEY={key}\n")
    else:
        env_path.write_text(f"API_KEY={key}\n")

    logger.info(
        "Auto-generated API key and saved to %s",
        env_path,
    )
    logger.info(
        "Your API key: %s", key
    )
    logger.info(
        "Use this key in the Authorization header: "
        "Bearer %s", key
    )
    return key


def _auto_generate_jwt_secret() -> str:
    """Generate a JWT signing secret, save to .env.

    Called on first startup when JWT_SECRET is not
    configured. Persisted so restarts reuse it.
    """
    secret = secrets.token_hex(32)
    env_path = (
        Path(__file__).resolve().parent.parent / ".env"
    )

    if env_path.exists():
        content = env_path.read_text()
        if "JWT_SECRET=" in content:
            lines = content.splitlines()
            lines = [
                f"JWT_SECRET={secret}"
                if line.startswith("JWT_SECRET=")
                else line
                for line in lines
            ]
            env_path.write_text(
                "\n".join(lines) + "\n"
            )
        else:
            with open(env_path, "a") as f:
                f.write(f"JWT_SECRET={secret}\n")
    else:
        env_path.write_text(
            f"JWT_SECRET={secret}\n"
        )

    logger.info(
        "Auto-generated JWT secret saved to %s",
        env_path,
    )
    return secret


settings = Settings()
