"""Security graph endpoint — all-resource graph with
attack path analysis.

Provides GET /api/v1/inventory/graph which returns
a SecurityGraph containing nodes (resources), edges
(relationships), and flagged attack paths.

Note: The legacy IAM-only graph lives at
/api/v1/iam/graph and is NOT modified here.
"""

import logging

from fastapi import APIRouter, Depends, Query

from app.dependencies import (
    get_resource_store,
    get_settings,
    get_state_manager,
)
from app.graph.builder import SecurityGraphBuilder
from app.graph.models import SecurityGraph
from app.pipeline.resource_store import ResourceStore
from app.pipeline.state_manager import StateManager

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["security-graph"],
)


@router.get(
    "/inventory/graph",
    response_model=SecurityGraph,
)
def get_security_graph(
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
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    settings=Depends(get_settings),
) -> SecurityGraph:
    """Return the security resource graph.

    Nodes represent AWS resources; edges represent
    inferred relationships (VPC containment, IAM
    roles, security groups, etc.).  Edges on
    critical lateral-movement paths are flagged
    as attack_path=True.

    Query params:
        region: Filter resources to a single AWS
            region (defaults to settings.aws_region).
        account_id: Filter to a specific account
            (defaults to settings.aws_account_id).

    Returns:
        SecurityGraph with nodes, edges, and counts.
    """
    effective_account = (
        account_id
        if account_id
        else settings.aws_account_id
    )
    effective_region = (
        region if region else settings.aws_region
    )

    # Fetch resources from inventory.
    try:
        resources = store.query_by_account(
            effective_account,
            effective_region,
            limit=5000,
        )
    except Exception:
        logger.exception(
            "Failed to fetch resources for "
            "security graph"
        )
        resources = []

    # Fetch active violations.
    try:
        violations = state_manager.query_by_account(
            effective_account,
            effective_region,
            limit=5000,
        )
    except Exception:
        logger.exception(
            "Failed to fetch violations for "
            "security graph"
        )
        violations = []

    builder = SecurityGraphBuilder(
        resources=resources,
        violations=violations,
    )
    return builder.build()
