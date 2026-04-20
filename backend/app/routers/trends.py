"""Trends history API endpoint."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import (
    require_any_authenticated,
)
from app.dependencies import get_snapshot_manager
from app.pipeline.snapshot_manager import (
    SnapshotManager,
)

router = APIRouter(
    tags=["trends"],
    dependencies=[Depends(require_any_authenticated)],
)


@router.get("/trends/history")
def get_trends_history(
    account_id: str = Query(
        ...,
        description="AWS account ID",
    ),
    days: int = Query(
        30,
        ge=1,
        le=90,
        description="Number of days of history",
    ),
    snapshot_manager: SnapshotManager = Depends(
        get_snapshot_manager
    ),
) -> dict:
    """Return daily compliance snapshots.

    One record per scan day for the requested account.
    """
    since = (
        datetime.now(UTC) - timedelta(days=days)
    ).strftime("%Y-%m-%d")
    snapshots = snapshot_manager.get_snapshots(
        account_id=account_id,
        since=since,
    )
    return {"snapshots": snapshots}
