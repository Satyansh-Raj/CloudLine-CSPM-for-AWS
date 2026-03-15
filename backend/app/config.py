"""Application configuration via environment variables."""

import logging
import secrets
from pathlib import Path

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from env vars / .env."""

    # AWS
    aws_region: str = "us-east-1"
    aws_account_id: str = ""

    # Authentication
    api_key: str = "change-me-in-env"

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
    # SNS (gracefully skips when empty)
    sns_alert_topic_arn: str = ""

    # WebSocket
    ws_heartbeat_interval: int = 30
    ws_max_connections: int = 100

    # CORS
    cors_origins: str = "http://localhost:5173"

    # Rate limiting
    rate_limit: str = "60/minute"

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


settings = Settings()
