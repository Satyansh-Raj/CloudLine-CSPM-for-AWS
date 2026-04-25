"""Inventory REST API — resource listing, filtering,
and summary endpoints."""

import logging
from collections import Counter

import boto3
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app.auth.account_access import assert_account_allowed
from app.auth.dependencies import (
    get_current_user,
    require_any_authenticated,
)
from app.auth.models import User
from app.dependencies import (
    get_account_store,
    get_boto3_session,
    get_resource_store,
    get_settings,
)
from app.pipeline.account_store import AccountStore
from app.pipeline.resource_store import ResourceStore

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["inventory"],
    dependencies=[Depends(require_any_authenticated)],
)


_cached_regions: list[str] | None = None


def _discover_regions(
    session: boto3.Session,
) -> list[str]:
    """Discover all enabled AWS regions via EC2 API.

    Result is cached after the first successful call.
    Returns empty list on failure (caller should fall
    back to settings.aws_regions).
    """
    global _cached_regions
    if _cached_regions is not None:
        return _cached_regions
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_regions(
            AllRegions=False,
        )
        regions = sorted(
            r["RegionName"]
            for r in resp.get("Regions", [])
        )
        if regions:
            _cached_regions = regions
            return regions
    except Exception as exc:
        logger.warning(
            "Region discovery failed, using config "
            "fallback: %s",
            exc,
        )
    return []


def reset_region_cache() -> None:
    """Clear the cached region list (for testing)."""
    global _cached_regions
    _cached_regions = None


def _resource_to_dict(r) -> dict:
    """Convert a ResourceRecord to API response."""
    return {
        "resource_id": r.resource_id,
        "resource_name": r.resource_name,
        "resource_type": r.resource_type,
        "technology_category": r.technology_category,
        "service": r.service,
        "region": r.region,
        "account_id": r.account_id,
        "exposure": r.exposure,
        "environment": r.environment,
        "owner": r.owner,
        "tags": r.tags,
        "is_active": r.is_active,
        "last_seen": r.last_seen,
        "violation_count": r.violation_count,
        "critical_violations": r.critical_violations,
        "high_violations": r.high_violations,
        "risk_score": r.risk_score,
        "connected_to": r.connected_to,
        "managed_by": r.managed_by,
        "belongs_to": r.belongs_to,
        "created_at": r.created_at,
        # Data classification fields (Batch 6)
        "data_sensitivity": r.data_sensitivity,
        "data_types": r.data_types,
        "compliance_gaps": r.compliance_gaps,
    }


@router.get("/inventory/regions")
def list_regions(
    session=Depends(get_boto3_session),
    settings=Depends(get_settings),
) -> dict:
    """Return all enabled AWS regions.

    Uses EC2 describe_regions() for dynamic discovery,
    falling back to settings.aws_regions on error.
    """
    discovered = _discover_regions(session)
    regions = discovered or settings.aws_regions
    return {
        "regions": regions,
        "default": settings.aws_regions[0],
    }


@router.get("/inventory")
def list_inventory(
    category: str | None = Query(
        None,
        description="Filter by technology_category",
    ),
    exposure: str | None = Query(
        None,
        description="Filter by exposure level",
    ),
    service: str | None = Query(
        None,
        description="Filter by AWS service",
    ),
    search: str | None = Query(
        None,
        description="Search by name or ID",
    ),
    limit: int = Query(
        200,
        ge=1,
        le=5000,
        description="Max results",
    ),
    region: str | None = Query(
        None,
        description="Filter by AWS region",
    ),
    account_id: str | None = Query(
        None,
        description="Filter by AWS account ID",
    ),
    store: ResourceStore = Depends(
        get_resource_store
    ),
    account_store: AccountStore = Depends(
        get_account_store
    ),
    settings=Depends(get_settings),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """List resources with optional filters.

    Filter priority: category > exposure > service >
    account (default). Search is applied in-memory
    after the primary query. Only active resources
    are returned.
    """
    effective_account = (
        account_id or settings.aws_account_id
    )
    assert_account_allowed(current_user, effective_account)
    is_cross_account = (
        account_id
        and account_id != settings.aws_account_id
    )
    if is_cross_account:
        acct_obj = account_store.get_account(account_id)
        acct_regions = (
            acct_obj.regions
            if acct_obj and acct_obj.regions
            else [settings.aws_region]
        )
    else:
        acct_obj = None
        acct_regions = None

    if category:
        resources = store.query_by_category(
            category, limit=limit
        )
    elif exposure:
        resources = store.query_by_exposure(
            exposure, limit=limit
        )
    elif service:
        resources = store.query_by_service(
            service, limit=limit
        )
    else:
        if region:
            resources = store.query_by_account(
                effective_account, region, limit=limit
            )
        else:
            resources = []
            for r in (acct_regions or [settings.aws_region]):
                resources.extend(
                    store.query_by_account(
                        effective_account, r, limit=limit
                    )
                )

    # For GSI paths, filter by account_id in-memory
    if (category or exposure or service) and account_id:
        resources = [
            r for r in resources
            if r.account_id == account_id
        ]

    # Region filter for GSI paths (category/exposure/
    # service) which cannot filter by PK in DynamoDB.
    if region and resources:
        resources = [
            r for r in resources
            if r.region == region
        ]

    # Filter out soft-deleted resources
    resources = [
        r for r in resources if r.is_active
    ]

    if search:
        q = search.lower()
        resources = [
            r for r in resources
            if q in r.resource_name.lower()
            or q in r.resource_id.lower()
        ]

    return [_resource_to_dict(r) for r in resources]


@router.get("/inventory/summary")
def inventory_summary(
    region: str | None = Query(
        None,
        description=(
            "Filter by AWS region. Omit to "
            "aggregate across all scanned regions."
        ),
    ),
    account_id: str | None = Query(
        None,
        description="Filter by AWS account ID",
    ),
    store: ResourceStore = Depends(
        get_resource_store
    ),
    account_store: AccountStore = Depends(
        get_account_store
    ),
    session=Depends(get_boto3_session),
    settings=Depends(get_settings),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Aggregated inventory statistics.

    When no region is specified, aggregates across all
    scanned regions (discovered + configured). Only
    active resources (is_active=true) are counted.
    """
    effective_account = (
        account_id or settings.aws_account_id
    )
    assert_account_allowed(current_user, effective_account)
    is_cross_account = (
        account_id
        and account_id != settings.aws_account_id
    )
    if region:
        target_regions = [region]
    elif is_cross_account:
        acct_obj = account_store.get_account(account_id)
        target_regions = (
            acct_obj.regions
            if acct_obj and acct_obj.regions
            else settings.aws_regions
        )
    else:
        discovered = _discover_regions(session)
        target_regions = (
            discovered or settings.aws_regions
        )
    items = store.summary_by_account(
        effective_account,
        regions=target_regions,
    )

    by_category: Counter = Counter()
    by_exposure: Counter = Counter()
    by_service: Counter = Counter()

    active_count = 0
    for item in items:
        # Skip inactive / soft-deleted resources
        if not item.get("is_active", True):
            continue
        active_count += 1
        cat = item.get("technology_category", "")
        if cat:
            by_category[cat] += 1
        exp = item.get("exposure", "")
        if exp:
            by_exposure[exp] += 1
        svc = item.get("service", "")
        if svc:
            by_service[svc] += 1

    return {
        "total": active_count,
        "by_category": dict(by_category),
        "by_exposure": dict(by_exposure),
        "by_service": dict(by_service),
    }


@router.get("/inventory/detail")
def get_inventory_detail(
    resource_type: str = Query(
        ..., description="Resource type"
    ),
    resource_id: str = Query(
        ..., description="Resource ARN"
    ),
    account_id: str | None = Query(
        None,
        description="AWS account ID override",
    ),
    store: ResourceStore = Depends(
        get_resource_store
    ),
    settings=Depends(get_settings),
    current_user: User = Depends(get_current_user),
):
    """Get a single resource by type and ID."""
    assert_account_allowed(
        current_user,
        account_id or settings.aws_account_id,
    )
    resource = store.get_resource(
        account_id or settings.aws_account_id,
        settings.aws_region,
        resource_type,
        resource_id,
    )
    if not resource:
        return JSONResponse(
            status_code=404,
            content={"detail": "Resource not found"},
        )
    return _resource_to_dict(resource)


@router.get("/inventory/data-classification")
def get_data_classification(
    resource_type: str = Query(
        ..., description="Resource type"
    ),
    resource_id: str = Query(
        ..., description="Resource ARN"
    ),
    account_id: str | None = Query(
        None,
        description="AWS account ID override",
    ),
    store: ResourceStore = Depends(
        get_resource_store
    ),
    settings=Depends(get_settings),
    current_user: User = Depends(get_current_user),
):
    """Get data classification for a single resource.

    Returns the data_types, sensitivity, frameworks,
    compliance_requirements, and compliance_gaps for
    the requested resource.

    Returns 404 if the resource is not found.
    """
    assert_account_allowed(
        current_user,
        account_id or settings.aws_account_id,
    )
    resource = store.get_resource(
        account_id or settings.aws_account_id,
        settings.aws_region,
        resource_type,
        resource_id,
    )
    if not resource:
        return JSONResponse(
            status_code=404,
            content={"detail": "Resource not found"},
        )
    return {
        "resource_id": resource.resource_id,
        "resource_type": resource.resource_type,
        "data_types": resource.data_types,
        "sensitivity": resource.data_sensitivity,
        "compliance_gaps": resource.compliance_gaps,
    }


@router.get("/inventory/data-summary")
def get_data_summary(
    account_id: str | None = Query(
        None,
        description="AWS account ID override",
    ),
    store: ResourceStore = Depends(
        get_resource_store
    ),
    settings=Depends(get_settings),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Aggregated data-classification statistics.

    Returns:
        by_type: count of resources per data type
            label (a resource counts once per type it
            carries).
        by_sensitivity: count per sensitivity level.
        by_framework: count of resources per compliance
            framework (derived from ComplianceMapper).
    """
    assert_account_allowed(
        current_user,
        account_id or settings.aws_account_id,
    )
    from app.inventory.compliance_mapper import (
        ComplianceMapper,
    )

    resources = store.query_by_account(
        account_id or settings.aws_account_id,
        settings.aws_region,
        limit=5000,
    )
    mapper = ComplianceMapper()

    by_type: Counter = Counter()
    by_sensitivity: Counter = Counter()
    by_framework: Counter = Counter()

    for res in resources:
        # Count each data_type label this resource has
        for dt in res.data_types:
            by_type[dt] += 1

        if res.data_sensitivity not in (
            "unknown",
            "",
        ):
            by_sensitivity[res.data_sensitivity] += 1

        # Derive frameworks from the resource's types
        # via the mapper (avoids re-storing framework
        # data on each record).
        from app.inventory.data_classifier import (
            DataClassification,
        )

        if res.data_types:
            classification = DataClassification(
                sensitivity=res.data_sensitivity,
                data_types=res.data_types,
                confidence="high",
                source="tag",
            )
            result = mapper.map(classification)
            for fw in result.frameworks:
                by_framework[fw] += 1

    return {
        "by_type": dict(by_type),
        "by_sensitivity": dict(by_sensitivity),
        "by_framework": dict(by_framework),
    }
