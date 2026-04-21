"""Jira ticketing endpoint for CloudLine violations.

POST /api/v1/violations/{account_id}/{region}/
     {check_id}/{resource_id}/ticket

Creates a Jira issue for a violation and stores the
ticket ID/URL back on the violation state record.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import require_admin_or_operator
from app.dependencies import (
    get_jira_client,
    get_settings,
    get_state_manager,
)
from app.jira.client import JiraClient
from app.jira.models import (
    CreateTicketFromViolation,
    JiraTicketResponse,
)
from app.pipeline.state_manager import StateManager

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["jira"],
    dependencies=[Depends(require_admin_or_operator)],
)


@router.post(
    "/violations"
    "/{account_id}"
    "/{region}"
    "/{check_id}"
    "/{resource_id:path}"
    "/ticket",
    response_model=JiraTicketResponse,
)
def create_violation_ticket(
    account_id: str,
    region: str,
    check_id: str,
    resource_id: str,
    body: CreateTicketFromViolation = (
        CreateTicketFromViolation()
    ),
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    jira: JiraClient | None = Depends(
        get_jira_client
    ),
    settings=Depends(get_settings),
) -> JiraTicketResponse:
    """Create a Jira ticket for a violation.

    Looks up the violation in DynamoDB, creates a
    Jira issue, and stores the ticket info back on
    the violation record.

    Args:
        account_id: AWS account ID.
        region: AWS region.
        check_id: Policy check ID.
        resource_id: Resource ARN (path-encoded).
        body: Optional overrides for the ticket.
        state_manager: Injected StateManager.
        jira: Injected JiraClient (None if uncfg).
        settings: Injected application settings.

    Returns:
        JiraTicketResponse with ticket details.

    Raises:
        HTTPException 503: Jira not configured.
        HTTPException 404: Violation not found.
        HTTPException 409: Ticket already exists.
    """
    if jira is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Jira integration is not configured. "
                "Set JIRA_URL, JIRA_EMAIL, and "
                "JIRA_API_TOKEN environment variables."
            ),
        )

    state = state_manager.get_state(
        account_id=account_id,
        region=region,
        check_id=check_id,
        resource_arn=resource_id,
    )
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Violation not found: "
                f"{account_id}/{region}/"
                f"{check_id}/{resource_id}"
            ),
        )

    if state.ticket_id:
        raise HTTPException(
            status_code=409,
            detail=(
                "Ticket already exists for this violation. "
                f"Existing ticket: {state.ticket_id}"
            ),
        )

    description = (
        jira.format_violation_description(state)
    )

    # Severity → Jira priority mapping
    _priority_map = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    default_priority = _priority_map.get(
        state.severity, "Medium"
    )

    summary = (
        body.summary
        or (
            f"[CloudLine] {state.severity.upper()}: "
            f"{state.check_id} — "
            f"{state.resource_arn}"
        )
    )
    priority = body.priority or default_priority
    labels = body.labels if body.labels else []

    ticket = jira.create_issue(
        project_key=settings.jira_project_key or "SEC",
        summary=summary,
        description=description,
        issue_type="Task",
        priority=priority,
        labels=labels,
    )

    # Persist ticket info on the violation record
    updated = state.model_copy(
        update={
            "ticket_id": ticket.ticket_id,
            "ticket_url": ticket.ticket_url,
        }
    )
    state_manager.put_state(updated)

    logger.info(
        "Ticket %s created for %s/%s",
        ticket.ticket_key,
        check_id,
        resource_id,
    )

    return ticket


@router.delete(
    "/violations"
    "/{account_id}"
    "/{region}"
    "/{check_id}"
    "/{resource_id:path}"
    "/ticket",
)
def delete_violation_ticket(
    account_id: str,
    region: str,
    check_id: str,
    resource_id: str,
    state_manager: StateManager = Depends(
        get_state_manager
    ),
    jira: JiraClient | None = Depends(
        get_jira_client
    ),
) -> dict:
    """Delete a Jira ticket and unlink from violation.

    Deletes the issue from Jira Cloud, then clears
    ticket_id and ticket_url on the violation record.

    Args:
        account_id: AWS account ID.
        region: AWS region.
        check_id: Policy check ID.
        resource_id: Resource ARN (path-encoded).
        state_manager: Injected StateManager.
        jira: Injected JiraClient.

    Returns:
        Confirmation message.

    Raises:
        HTTPException 404: Violation or ticket not found.
        HTTPException 503: Jira not configured.
    """
    if jira is None:
        raise HTTPException(
            status_code=503,
            detail="Jira integration is not configured.",
        )

    state = state_manager.get_state(
        account_id=account_id,
        region=region,
        check_id=check_id,
        resource_arn=resource_id,
    )
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Violation not found: "
                f"{account_id}/{region}/"
                f"{check_id}/{resource_id}"
            ),
        )

    if not state.ticket_id:
        raise HTTPException(
            status_code=404,
            detail="No ticket linked to this violation.",
        )

    # Delete the issue from Jira
    try:
        jira.delete_issue(state.ticket_id)
    except Exception as exc:
        logger.error(
            "Failed to delete Jira issue %s: %s",
            state.ticket_id,
            exc,
        )
        raise HTTPException(
            status_code=502,
            detail=(
                f"Failed to delete Jira issue: {exc}"
            ),
        ) from exc

    # Clear ticket info on the violation record
    updated = state.model_copy(
        update={
            "ticket_id": None,
            "ticket_url": None,
        }
    )
    state_manager.put_state(updated)

    logger.info(
        "Ticket %s deleted and unlinked from %s/%s",
        state.ticket_id,
        check_id,
        resource_id,
    )

    return {"message": "Ticket deleted successfully"}
