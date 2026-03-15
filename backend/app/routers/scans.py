"""Scan trigger API endpoint.

POST /scans runs a full AWS collection, evaluates
all policies via OPA, persists results to DynamoDB,
and returns a summary.
"""

from datetime import UTC, datetime

from uuid import uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
)

from app.collectors.orchestrator import (
    CollectionOrchestrator,
)
from app.dependencies import (
    get_boto3_session,
    get_evaluator,
    get_settings,
    get_state_manager,
    get_ws_manager,
)
from app.pipeline.ws_manager import format_drift_event
from app.engine.evaluator import PolicyEvaluator
from app.pipeline.alert_generator import AlertGenerator
from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
    ViolationState,
)
from app.pipeline.risk_scorer import RiskScorer
from app.pipeline.state_manager import StateManager

import asyncio

router = APIRouter(
    tags=["scans"],
)

_scorer = RiskScorer()
_scan_results: dict[str, dict] = {}
_event_loop: asyncio.AbstractEventLoop | None = None


def _run_scan(
    scan_id: str,
    session,
    settings,
    evaluator: PolicyEvaluator,
    state_manager: StateManager,
):
    """Run scan in background thread."""
    try:
        _scan_results[scan_id] = {"status": "running", "scan_id": scan_id}

        # New orchestrator per scan is intentional —
        # collectors hold per-scan state and are cheap.
        orchestrator = CollectionOrchestrator(
            session=session,
            account_id=settings.aws_account_id,
            region=settings.aws_region,
        )
        input_data = orchestrator.collect_full()
        violations = evaluator.evaluate_all(input_data)

        now = (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        account_id = settings.aws_account_id
        region = settings.aws_region
        pk = f"{account_id}#{region}"
        persisted = 0

        # Collect alerts to publish to SNS after saving state
        drift_alerts: list[DriftAlert] = []

        for v in violations:
            resource = getattr(v, "resource", "")
            svc = getattr(v, "domain", "")
            dims = _scorer.score(
                violation=v,
                resource_data=input_data.get(svc, {}),
                service=svc,
            )
            existing = state_manager.get_state(
                account_id, region,
                v.check_id, resource,
            )
            first_seen = (
                existing.first_detected
                if existing
                else now
            )
            state = ViolationState(
                pk=pk,
                sk=f"{v.check_id}#{resource}",
                check_id=v.check_id,
                status=v.status,
                severity=v.severity,
                domain=svc,
                resource_arn=resource,
                reason=getattr(v, "reason", ""),
                risk_score=dims.composite,
                first_detected=first_seen,
                last_evaluated=now,
            )
            if state_manager.put_state(state):
                persisted += 1

            # Build a DriftAlert for each new alarm so SNS can be notified
            if v.status == "alarm":
                # Determine drift type — NEW_VIOLATION if previously ok/absent
                prev_status = existing.status if existing else None
                drift_type = (
                    DriftType.NEW_VIOLATION
                    if (prev_status is None or prev_status != "alarm")
                    else DriftType.NO_CHANGE
                )
                # Only alert on genuine new/returning violations
                if drift_type == DriftType.NEW_VIOLATION:
                    try:
                        sev = AlertSeverity(v.severity.lower())
                    except (ValueError, AttributeError):
                        sev = AlertSeverity.MEDIUM
                    drift_alerts.append(
                        DriftAlert(
                            drift_type=drift_type,
                            check_id=v.check_id,
                            resource_arn=resource,
                            previous_status=prev_status or "",
                            current_status="alarm",
                            severity=sev,
                            risk_score=dims.composite,
                            trigger_event="FullScan",
                            timestamp=now,
                            reason=getattr(v, "reason", ""),
                            account_id=account_id,
                            region=region,
                        )
                    )

        # ── Stale state cleanup ───────────────────────────────────────
        # Resources that existed in the previous scan but are now gone
        # (e.g. deleted via terraform destroy) should be marked "ok"
        # (resolved), NOT deleted. This keeps the full history intact
        # for the Trends page while removing them from the active alarm
        # count on the dashboard.
        fresh_keys: set[tuple[str, str]] = {
            (getattr(v, "check_id", ""), getattr(v, "resource", ""))
            for v in violations
        }
        existing_states = state_manager.query_by_account(
            account_id, region, limit=2000
        )
        stale_resolved = 0
        for old in existing_states:
            if (old.check_id, old.resource_arn) not in fresh_keys:
                # Only resolve if it was previously in alarm —
                # no-op if it was already ok/resolved
                if old.status == "alarm":
                    if state_manager.update_status(
                        account_id,
                        region,
                        old.check_id,
                        old.resource_arn,
                        new_status="ok",
                        reason="Resource no longer exists in AWS (auto-resolved)",
                    ):
                        stale_resolved += 1
                        logger.info(
                            "Auto-resolved missing resource: %s / %s",
                            old.check_id,
                            old.resource_arn,
                        )
        # ─────────────────────────────────────────────────────────────

        # Publish SNS alerts for new violations
        sns_published = 0
        if drift_alerts and settings.sns_alert_topic_arn:
            alert_gen = AlertGenerator(
                session=session,
                topic_arn=settings.sns_alert_topic_arn,
            )
            sns_published = alert_gen.publish_batch(drift_alerts)

        # Broadcast to WebSocket clients (bell icon)
        if drift_alerts and _event_loop is not None:
            ws_manager = get_ws_manager()
            for alert in drift_alerts:
                try:
                    _event_loop.call_soon_threadsafe(
                        lambda a=alert: _event_loop.create_task(
                            ws_manager.broadcast(
                                format_drift_event(a)
                            )
                        )
                    )
                except Exception:
                    pass


        alarms = sum(
            1 for v in violations
            if v.status == "alarm"
        )
        _scan_results[scan_id] = {
            "status": "completed",
            "scan_id": scan_id,
            "total_evaluated": len(violations),
            "violations": alarms,
            "compliant": len(violations) - alarms,
            "persisted": persisted,
            "stale_resolved": stale_resolved,
            "sns_alerts_sent": sns_published,
            "timestamp": now,
        }

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            "Scan %s failed: %s", scan_id, e, exc_info=True
        )
        _scan_results[scan_id] = {
            "status": "failed",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }


@router.post("/scans", status_code=202)
async def trigger_scan(
    background_tasks: BackgroundTasks,
    session=Depends(get_boto3_session),
    settings=Depends(get_settings),
    evaluator: PolicyEvaluator = Depends(
        get_evaluator
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
):
    """Trigger a full scan asynchronously.

    Returns 202 with a scan_id. The scan runs
    in a background task.
    """
    global _event_loop
    _event_loop = asyncio.get_event_loop()
    scan_id = str(uuid4())
    background_tasks.add_task(
        _run_scan,
        scan_id,
        session,
        settings,
        evaluator,
        state_manager,
    )
    return {
        "scan_id": scan_id,
        "status": "queued",
    }


@router.get("/scans/{scan_id}")
def get_scan_result(scan_id: str):
    """Get the result of a background scan."""
    result = _scan_results.get(scan_id)
    if result is None:
        return {
            "scan_id": scan_id,
            "status": "running",
        }
    return result


