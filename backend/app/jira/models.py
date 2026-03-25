"""Pydantic models for Jira integration."""

from pydantic import BaseModel, ConfigDict


class JiraTicketRequest(BaseModel):
    """Request body for creating a Jira ticket.

    Attributes:
        summary: Issue summary / title.
        description: Full issue description.
        issue_type: Jira issue type (default Bug).
        priority: Jira priority level.
        labels: List of label strings.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    description: str
    issue_type: str = "Bug"
    priority: str = "Medium"
    labels: list[str] = []


class JiraTicketResponse(BaseModel):
    """Response after a Jira ticket is created.

    Attributes:
        ticket_id: Numeric Jira issue ID.
        ticket_url: Browser URL to the ticket.
        ticket_key: Human-readable key (e.g. SEC-42).
    """

    model_config = ConfigDict(extra="forbid")

    ticket_id: str
    ticket_url: str
    ticket_key: str


class CreateTicketFromViolation(BaseModel):
    """Optional override fields when creating a ticket
    from an existing violation.

    All fields are optional — omitted fields use
    values auto-generated from the violation state.

    Attributes:
        summary: Override the auto-generated summary.
        priority: Override the default priority.
        labels: Extra labels to attach to the ticket.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str | None = None
    priority: str | None = None
    labels: list[str] = []
