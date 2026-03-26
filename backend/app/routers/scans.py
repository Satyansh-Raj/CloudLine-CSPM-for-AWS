"""Scan trigger API endpoint.

POST /scans runs a full AWS collection, evaluates
all policies via OPA, persists results to DynamoDB,
and returns a summary.

Multi-region support (F3 Batch 7):
  - IAM is collected ONCE globally (not per region).
  - Regional collectors run in parallel via
    ThreadPoolExecutor, one task per region.
  - Results are aggregated across all regions.
"""

import asyncio
import concurrent.futures
import logging
from datetime import UTC, datetime
from uuid import uuid4

import boto3

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
)

from app.collectors.orchestrator import (
    CollectionOrchestrator,
)
from app.dependencies import (
    get_account_store,
    get_boto3_session,
    get_evaluator,
    get_resource_store,
    get_session_factory,
    get_settings,
    get_state_manager,
    get_ws_manager,
)
from app.engine.evaluator import PolicyEvaluator
from app.inventory.classifier import (
    ResourceClassifier,
)
from app.models.aws_input import UnifiedAWSInput
from app.pipeline.alert_generator import AlertGenerator
from app.pipeline.models import (
    AlertSeverity,
    DriftAlert,
    DriftType,
    ViolationState,
)
from app.pipeline.resource_store import ResourceStore
from app.pipeline.risk_scorer import RiskScorer
from app.pipeline.state_manager import StateManager
from app.pipeline.ws_manager import format_drift_event

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["scans"],
)

_scorer = RiskScorer()
_scan_results: dict[str, dict] = {}
_event_loop: asyncio.AbstractEventLoop | None = None


# ---------------------------------------------------------------------------
# Per-region processing helpers
# ---------------------------------------------------------------------------

def _process_region(
    region: str,
    input_data: dict,
    session,
    settings,
    evaluator: PolicyEvaluator,
    state_manager: StateManager,
    resource_store,
    now: str,
    account_id: str | None = None,
) -> dict:
    """Run evaluation + state management for ONE region.

    Returns a summary dict with violation counts,
    persisted counts, drift alerts, and inventory counts.

    Args:
        account_id: Override the account to use.
            Falls back to settings.aws_account_id when
            not provided (backward compatibility).
    """
    if account_id is None:
        account_id = settings.aws_account_id
    pk = f"{account_id}#{region}"
    persisted = 0
    stale_resolved = 0
    inventory_persisted = 0
    drift_alerts: list[DriftAlert] = []

    violations = evaluator.evaluate_all(input_data)

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

        if v.status == "alarm":
            prev_status = (
                existing.status if existing else None
            )
            drift_type = (
                DriftType.NEW_VIOLATION
                if (
                    prev_status is None
                    or prev_status != "alarm"
                )
                else DriftType.NO_CHANGE
            )
            if drift_type == DriftType.NEW_VIOLATION:
                try:
                    sev = AlertSeverity(
                        v.severity.lower()
                    )
                except (ValueError, AttributeError):
                    sev = AlertSeverity.MEDIUM
                drift_alerts.append(
                    DriftAlert(
                        drift_type=drift_type,
                        check_id=v.check_id,
                        resource_arn=resource,
                        previous_status=(
                            prev_status or ""
                        ),
                        current_status="alarm",
                        severity=sev,
                        risk_score=dims.composite,
                        trigger_event="FullScan",
                        timestamp=now,
                        reason=getattr(
                            v, "reason", ""
                        ),
                        account_id=account_id,
                        region=region,
                    )
                )

    # Stale state cleanup
    fresh_keys: set[tuple[str, str]] = {
        (
            getattr(v, "check_id", ""),
            getattr(v, "resource", ""),
        )
        for v in violations
    }
    fresh_check_ids: set[str] = {
        getattr(v, "check_id", "")
        for v in violations
    }
    existing_states = state_manager.query_by_account(
        account_id, region, limit=2000
    )
    for old in existing_states:
        # Purge violations whose check_id no longer
        # exists in the policy set (renamed/removed).
        if old.check_id not in fresh_check_ids:
            state_manager.delete_state(
                account_id,
                region,
                old.check_id,
                old.resource_arn,
            )
            logger.info(
                "Purged orphaned check_id: %s / %s",
                old.check_id,
                old.resource_arn,
            )
            continue

        if (
            old.check_id,
            old.resource_arn,
        ) not in fresh_keys:
            if old.status == "alarm":
                if state_manager.update_status(
                    account_id,
                    region,
                    old.check_id,
                    old.resource_arn,
                    new_status="ok",
                    reason=(
                        "Resource no longer exists "
                        "in AWS (auto-resolved)"
                    ),
                ):
                    stale_resolved += 1
                    logger.info(
                        "Auto-resolved missing resource:"
                        " %s / %s",
                        old.check_id,
                        old.resource_arn,
                    )

    # Resource inventory
    if resource_store:
        try:
            input_model = UnifiedAWSInput(**input_data)
            clf = ResourceClassifier(
                account_id, region
            )
            resource_records = clf.classify_all(
                input_model
            )

            try:
                from app.inventory.compliance_mapper import ComplianceMapper
                from app.inventory.data_classifier import DataClassifier
                data_clf = DataClassifier(session)
                mapper = ComplianceMapper()
                clf.enrich_with_data_classification(
                    resource_records,
                    data_clf,
                    mapper,
                )
            except Exception as _dc_err:
                logger.warning(
                    "Data classification enrichment"
                    " failed (non-fatal): %s",
                    _dc_err,
                )

            clf.enrich_with_violations(
                resource_records, violations
            )

            for rec in resource_records:
                if resource_store.put_resource(rec):
                    inventory_persisted += 1

            # Only count records whose effective region
            # matches this scan region.  S3 buckets may
            # have a different true region (via
            # region_override) — we must NOT include them
            # in `seen` so the old stale record for
            # this scan region gets deactivated.
            seen = {
                (r.resource_type, r.resource_id)
                for r in resource_records
                if r.region == region
            }
            existing = resource_store.query_by_account(
                account_id, region, limit=5000,
            )
            for ex in existing:
                key = (
                    ex.resource_type,
                    ex.resource_id,
                )
                if (
                    ex.is_active
                    and key not in seen
                ):
                    resource_store.deactivate_resource(
                        account_id,
                        region,
                        ex.resource_type,
                        ex.resource_id,
                    )
        except Exception as e:
            logger.warning(
                "Inventory classification failed"
                " (non-fatal): %s",
                e,
            )

    alarms = sum(
        1 for v in violations if v.status == "alarm"
    )
    return {
        "region": region,
        "total_evaluated": len(violations),
        "violations": alarms,
        "compliant": len(violations) - alarms,
        "persisted": persisted,
        "stale_resolved": stale_resolved,
        "inventory_persisted": inventory_persisted,
        "drift_alerts": drift_alerts,
    }


def _collect_region(
    region: str,
    session,
    account_id: str,
    iam_data: dict,
) -> dict:
    """Collect regional services for ONE region and
    merge in the global IAM data.

    Creates a region-scoped boto3 session so every
    collector's ``session.client(...)`` call targets
    the correct region.

    Returns the merged input_data dict ready for OPA.
    """
    # Build a session pinned to this region.
    # Reuse credentials from the original session
    # (important for AssumeRole / multi-account).
    creds = session.get_credentials()
    if creds:
        frozen = creds.get_frozen_credentials()
        region_session = boto3.Session(
            aws_access_key_id=frozen.access_key,
            aws_secret_access_key=frozen.secret_key,
            aws_session_token=frozen.token,
            region_name=region,
        )
    else:
        region_session = boto3.Session(
            region_name=region,
        )

    orch = CollectionOrchestrator(
        session=region_session,
        account_id=account_id,
        region=region,
    )
    regional = orch.collect_regional()
    # Merge IAM (global) into regional result
    merged = {**regional}
    for k, v in iam_data.items():
        if k not in merged:
            merged[k] = v
    return merged


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def _scan_one_account(
    account_id: str,
    regions: list[str],
    session,
    settings,
    evaluator: PolicyEvaluator,
    state_manager: StateManager,
    resource_store,
    now: str,
) -> tuple[dict, list]:
    """Scan all regions for a single AWS account.

    Used by both single-account (fallback) and
    multi-account paths in _run_scan.

    Returns:
        Tuple of (totals_dict, drift_alerts_list).
    """
    # ── Collect IAM ONCE per account ─────────────────
    iam_orch = CollectionOrchestrator(
        session=session,
        account_id=account_id,
        region=regions[0],
    )
    iam_data = iam_orch.collect_iam()

    # ── Collect regional services in parallel ─────────
    max_workers = min(len(regions), 5)
    region_inputs: dict[str, dict] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as pool:
        futures = {
            pool.submit(
                _collect_region,
                region,
                session,
                account_id,
                iam_data,
            ): region
            for region in regions
        }
        for future in (
            concurrent.futures.as_completed(futures)
        ):
            region = futures[future]
            try:
                region_inputs[region] = (
                    future.result()
                )
            except Exception as exc:
                logger.error(
                    "Account %s region %s failed: %s",
                    account_id, region, exc,
                )
                region_inputs[region] = {
                    **iam_data,
                    "region": region,
                    "account_id": account_id,
                }

    # ── Evaluate & persist per region ─────────────────
    totals = {
        "total_evaluated": 0,
        "violations": 0,
        "compliant": 0,
        "persisted": 0,
        "stale_resolved": 0,
        "inventory_persisted": 0,
    }
    drift_alerts: list[DriftAlert] = []

    for region, input_data in region_inputs.items():
        try:
            summary = _process_region(
                region=region,
                input_data=input_data,
                session=session,
                settings=settings,
                evaluator=evaluator,
                state_manager=state_manager,
                resource_store=resource_store,
                now=now,
                account_id=account_id,
            )
            for key in totals:
                totals[key] += summary.get(key, 0)
            drift_alerts.extend(
                summary.get("drift_alerts", [])
            )
        except Exception as exc:
            logger.error(
                "Account %s region %s eval failed: %s",
                account_id, region, exc,
            )

    return totals, drift_alerts


def _run_scan(
    scan_id: str,
    session,
    settings,
    evaluator: PolicyEvaluator,
    state_manager: StateManager,
    resource_store: ResourceStore | None = None,
):
    """Run scan in background thread.

    Multi-account + multi-region flow:
      1. Load active accounts from AccountStore.
      2. If no accounts, fall back to single-account
         mode using settings.aws_account_id
         (backward compatibility).
      3. For each active account:
         a. Assume role via SessionFactory.
         b. Collect IAM once (global per account).
         c. Collect regional services in parallel.
         d. Evaluate + persist per region.
         e. Update last_scanned timestamp.
      4. Aggregate totals across all accounts/regions.
      5. SNS + WebSocket broadcast of drift alerts.
    """
    try:
        _scan_results[scan_id] = {
            "status": "running",
            "scan_id": scan_id,
        }

        now = (
            datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        totals = {
            "total_evaluated": 0,
            "violations": 0,
            "compliant": 0,
            "persisted": 0,
            "stale_resolved": 0,
            "inventory_persisted": 0,
        }
        all_drift_alerts: list[DriftAlert] = []
        all_regions: list[str] = []

        # ── Step 1: Load target accounts ─────────────
        account_store = get_account_store()
        active_accounts = account_store.list_active()

        if not active_accounts:
            # ── Fallback: single-account mode ─────────
            account_id = settings.aws_account_id
            regions: list[str] = settings.aws_regions
            all_regions.extend(regions)

            acct_totals, acct_alerts = (
                _scan_one_account(
                    account_id=account_id,
                    regions=regions,
                    session=session,
                    settings=settings,
                    evaluator=evaluator,
                    state_manager=state_manager,
                    resource_store=resource_store,
                    now=now,
                )
            )
            for key in totals:
                totals[key] += acct_totals.get(key, 0)
            all_drift_alerts.extend(acct_alerts)

        else:
            # ── Multi-account mode ────────────────────
            session_factory = get_session_factory()

            for account in active_accounts:
                try:
                    assumed = (
                        session_factory.get_session(
                            account
                        )
                    )
                    regions = account.regions
                    all_regions.extend(regions)

                    acct_totals, acct_alerts = (
                        _scan_one_account(
                            account_id=(
                                account.account_id
                            ),
                            regions=regions,
                            session=assumed,
                            settings=settings,
                            evaluator=evaluator,
                            state_manager=state_manager,
                            resource_store=resource_store,
                            now=now,
                        )
                    )
                    for key in totals:
                        totals[key] += (
                            acct_totals.get(key, 0)
                        )
                    all_drift_alerts.extend(acct_alerts)

                    account_store.update_last_scanned(
                        account.account_id, now
                    )
                except Exception as exc:
                    logger.error(
                        "Account %s scan failed: %s",
                        account.account_id, exc,
                    )

        # ── SNS + WebSocket broadcast ─────────────────
        sns_published = 0
        if (
            all_drift_alerts
            and settings.sns_alert_topic_arn
        ):
            alert_gen = AlertGenerator(
                session=session,
                topic_arn=settings.sns_alert_topic_arn,
            )
            sns_published = alert_gen.publish_batch(
                all_drift_alerts
            )

        if all_drift_alerts and _event_loop is not None:
            ws_manager = get_ws_manager()
            for alert in all_drift_alerts:
                try:
                    _event_loop.call_soon_threadsafe(
                        lambda a=alert: (
                            _event_loop.create_task(
                                ws_manager.broadcast(
                                    format_drift_event(a)
                                )
                            )
                        )
                    )
                except Exception:
                    pass

        # Invalidate IAM graph cache so the next
        # request fetches fresh post-scan data.
        from app.routers.iam_graph import (
            invalidate_cache as _invalidate_iam_cache,
        )
        _invalidate_iam_cache()

        _scan_results[scan_id] = {
            "status": "completed",
            "scan_id": scan_id,
            "regions_scanned": sorted(
                set(all_regions)
            ),
            **totals,
            "sns_alerts_sent": sns_published,
            "timestamp": now,
        }

    except Exception as e:
        logger.error(
            "Scan %s failed: %s", scan_id, e,
            exc_info=True,
        )
        _scan_results[scan_id] = {
            "status": "failed",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": (
                datetime.now(UTC)
                .isoformat()
                .replace("+00:00", "Z")
            ),
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
    resource_store: ResourceStore = Depends(
        get_resource_store
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
        resource_store,
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


