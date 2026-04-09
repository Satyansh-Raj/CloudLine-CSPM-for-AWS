"""Macie findings endpoint — reads from DynamoDB."""

import logging

from fastapi import APIRouter, Depends, Query

from app.dependencies import get_macie_store
from app.pipeline.macie_store import MacieFindingStore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["macie"])


@router.get("/macie/findings")
def list_macie_findings(
    bucket_name: str | None = Query(
        None,
        description="Filter by S3 bucket name",
    ),
    severity: str | None = Query(
        None,
        description="Filter by severity (Low/Medium/High)",
    ),
    account_id: str | None = Query(
        None,
        description="Filter by AWS account ID",
    ),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Max results",
    ),
    store: MacieFindingStore = Depends(get_macie_store),
) -> list[dict]:
    """List Macie findings from the last scan.

    Filter priority: bucket_name > severity > account_id.
    """
    return store.list_findings(
        account_id=account_id,
        bucket_name=bucket_name,
        severity=severity,
        limit=limit,
    )
