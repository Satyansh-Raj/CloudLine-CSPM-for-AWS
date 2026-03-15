"""Lambda entrypoint for CloudLine real-time detection.

Initializes the EventHandler pipeline once per warm
container and processes each EventBridge event.

Environment variables:
    AWS_REGION: AWS region (default: us-east-1)
    AWS_ACCOUNT_ID: AWS account ID (required)
    DYNAMODB_STATE_TABLE: DynamoDB table name
        (default: violation-state)
    OPA_BINARY_PATH: Path to OPA binary
        (default: /var/task/bin/opa)
    OPA_POLICY_DIR: Path to Rego policies directory
        (default: /var/task/policies)
    OPA_MODE: "cli" or "http" (default: cli)
"""
from __future__ import annotations

import json
import logging
import os
import sys

# Ensure app package is importable from Lambda root
sys.path.insert(0, "/var/task")

import boto3

from app.engine.evaluator import PolicyEvaluator
from app.engine.opa_client import create_opa_client
from app.pipeline.event_handler import EventHandler
from app.pipeline.state_manager import StateManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton — cached across warm invocations
# ---------------------------------------------------------------------------
_handler: EventHandler | None = None


def _build_handler() -> EventHandler:
    """Construct and wire the EventHandler pipeline.

    Called once per cold start; reused on warm invocations.
    """
    region = os.environ.get("AWS_REGION", "us-east-1")
    account_id = os.environ.get("AWS_ACCOUNT_ID", "")
    state_table = os.environ.get(
        "DYNAMODB_STATE_TABLE", "violation-state"
    )
    opa_binary = os.environ.get(
        "OPA_BINARY_PATH", "/var/task/bin/opa"
    )
    policy_dir = os.environ.get(
        "OPA_POLICY_DIR", "/var/task/policies"
    )
    opa_mode = os.environ.get("OPA_MODE", "cli")

    logger.info(
        "Initialising CloudLine handler: region=%s "
        "account=%s table=%s opa_mode=%s",
        region,
        account_id,
        state_table,
        opa_mode,
    )

    session = boto3.Session(region_name=region)

    opa_client = create_opa_client(
        mode=opa_mode,
        opa_binary=opa_binary,
        policy_dir=policy_dir,
    )

    evaluator = PolicyEvaluator(opa_client=opa_client)

    state_manager = StateManager(
        table_name=state_table,
        session=session,
    )

    return EventHandler(
        session=session,
        evaluator=evaluator,
        state_manager=state_manager,
        account_id=account_id,
        region=region,
    )


def lambda_handler(event: dict, context: object) -> dict:
    """AWS Lambda handler — processes an EventBridge event.

    Args:
        event: Raw EventBridge JSON envelope containing a
               CloudTrail record in the ``detail`` field.
        context: Lambda context object (unused).

    Returns:
        dict with keys:
            statusCode (int): 200 on success, 500 on error.
            alerts (int): Number of DriftAlert objects produced.
            drift_types (list[str]): Drift type for each alert.
            error (str): Present only when statusCode == 500.
    """
    global _handler  # noqa: PLW0603

    logger.info(
        "Received event: source=%s detail-type=%s",
        event.get("source", "unknown"),
        event.get("detail-type", "unknown"),
    )
    logger.debug("Full event: %s", json.dumps(event))

    try:
        # Initialise handler on first invocation (cold start)
        if _handler is None:
            _handler = _build_handler()

        alerts = _handler.process_event(event)

        drift_types = [a.drift_type for a in alerts]

        logger.info(
            "Pipeline complete: %d alert(s) — %s",
            len(alerts),
            drift_types,
        )

        return {
            "statusCode": 200,
            "alerts": len(alerts),
            "drift_types": drift_types,
        }

    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Unhandled exception in lambda_handler: %s", exc
        )
        return {
            "statusCode": 500,
            "alerts": 0,
            "drift_types": [],
            "error": str(exc),
        }
