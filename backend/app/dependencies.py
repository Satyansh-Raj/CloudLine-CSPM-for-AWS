"""Dependency injection for FastAPI."""

from functools import lru_cache

import boto3
from fastapi import Depends

from app.config import Settings, settings
from app.engine.evaluator import PolicyEvaluator
from app.engine.opa_client import (
    OPAClient,
    create_opa_client,
)
from app.jira.client import JiraClient
from app.auth.user_store import UserStore
from app.pipeline.account_store import AccountStore
from app.pipeline.macie_store import MacieFindingStore
from app.pipeline.resource_store import ResourceStore
from app.pipeline.session_factory import (
    AWSSessionFactory,
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
def get_resource_store() -> ResourceStore:
    """Singleton ResourceStore for inventory."""
    session = get_boto3_session()
    return ResourceStore(
        session=session,
        table_name=(
            settings.dynamodb_inventory_table
        ),
        endpoint_url=settings.dynamodb_endpoint,
    )


@lru_cache
def get_account_store() -> AccountStore:
    """Singleton AccountStore for target accounts."""
    session = get_boto3_session()
    return AccountStore(
        session=session,
        table_name=settings.dynamodb_accounts_table,
        endpoint_url=settings.dynamodb_endpoint,
    )


@lru_cache
def get_macie_store() -> MacieFindingStore:
    """Singleton MacieFindingStore for Macie findings."""
    session = get_boto3_session()
    return MacieFindingStore(
        session=session,
        table_name=settings.dynamodb_macie_table,
        endpoint_url=settings.dynamodb_endpoint,
    )


@lru_cache
def get_user_store() -> UserStore:
    """Singleton UserStore for the cloudline-users table."""
    session = get_boto3_session()
    return UserStore(
        session=session,
        table_name=settings.dynamodb_users_table,
        endpoint_url=settings.dynamodb_endpoint,
    )


@lru_cache
def get_session_factory() -> AWSSessionFactory:
    """Singleton AWSSessionFactory for AssumeRole."""
    session = get_boto3_session()
    return AWSSessionFactory(base_session=session)


@lru_cache
def get_ws_manager() -> ConnectionManager:
    """Singleton ConnectionManager for WebSocket."""
    return ConnectionManager()


def get_jira_client(
    cfg: Settings = Depends(get_settings),
) -> JiraClient | None:
    """Return a JiraClient if Jira is configured.

    Returns None when jira_url is empty, indicating
    the Jira integration is not set up.

    Args:
        cfg: Application settings (injected).

    Returns:
        JiraClient instance or None.
    """
    if not cfg.jira_url:
        return None
    return JiraClient(
        jira_url=cfg.jira_url,
        jira_email=cfg.jira_email,
        jira_api_token=cfg.jira_api_token,
    )
