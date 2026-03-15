"""Dependency injection for FastAPI."""

from functools import lru_cache

import boto3

from app.config import Settings, settings
from app.engine.evaluator import PolicyEvaluator
from app.engine.opa_client import (
    OPAClient,
    create_opa_client,
)
from app.pipeline.state_manager import StateManager
from app.pipeline.ws_manager import ConnectionManager


@lru_cache
def get_settings() -> Settings:
    return settings


@lru_cache
def get_boto3_session() -> boto3.Session:
    return boto3.Session(
        region_name=settings.aws_region
    )


@lru_cache
def get_opa_client() -> OPAClient:
    """Create OPA client based on OPA_MODE setting.

    Returns:
        OPACLIClient when mode="cli" (local dev).
        OPAHTTPClient when mode="http" (Docker).
    """
    return create_opa_client(
        mode=settings.opa_mode,
        opa_binary=settings.opa_binary_path,
        policy_dir=settings.opa_policy_dir,
        opa_http_url=settings.opa_http_url,
    )


def get_evaluator() -> PolicyEvaluator:
    # Not cached: PolicyEvaluator resolves policy
    # files from disk, so updates are picked up
    # without restart.
    return PolicyEvaluator(
        opa_client=get_opa_client()
    )


@lru_cache
def get_state_manager() -> StateManager:
    """Singleton StateManager for violation state."""
    session = get_boto3_session()
    return StateManager(
        session=session,
        table_name=settings.dynamodb_state_table,
        endpoint_url=settings.dynamodb_endpoint,
    )


@lru_cache
def get_ws_manager() -> ConnectionManager:
    """Singleton ConnectionManager for WebSocket."""
    return ConnectionManager()
