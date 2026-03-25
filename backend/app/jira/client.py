"""Jira REST API v3 client for CloudLine.

Handles issue creation via Basic auth and formats
violation details as plain-text descriptions
compatible with the Jira Cloud API v3 (ADF body).
"""

import logging

import httpx

from app.jira.models import JiraTicketResponse
from app.pipeline.models import ViolationState

logger = logging.getLogger(__name__)

_SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


class JiraClient:
    """Client for Jira Cloud REST API v3.

    Attributes:
        jira_url: Base URL of the Jira instance.
        jira_email: Jira account email for Basic auth.
        jira_api_token: API token for Basic auth.

    Example:
        >>> client = JiraClient(
        ...     jira_url="https://acme.atlassian.net",
        ...     jira_email="sec@acme.com",
        ...     jira_api_token="token",
        ... )
    """

    def __init__(
        self,
        jira_url: str,
        jira_email: str,
        jira_api_token: str,
    ):
        self.jira_url = jira_url.rstrip("/")
        self.jira_email = jira_email
        self.jira_api_token = jira_api_token

    def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = "Bug",
        priority: str = "Medium",
        labels: list[str] | None = None,
    ) -> JiraTicketResponse:
        """Create a new Jira issue.

        Args:
            project_key: Target Jira project key.
            summary: Issue title.
            description: Full issue description.
            issue_type: Jira issue type name.
            priority: Jira priority name.
            labels: List of label strings.

        Returns:
            JiraTicketResponse with id, key, url.

        Raises:
            httpx.HTTPStatusError: On non-2xx response.
            httpx.ConnectError: On network failure.
        """
        if labels is None:
            labels = []

        url = f"{self.jira_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description,
                                }
                            ],
                        }
                    ],
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
                "labels": labels,
            }
        }

        with httpx.Client() as http:
            resp = http.post(
                url,
                json=payload,
                auth=(
                    self.jira_email,
                    self.jira_api_token,
                ),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            if resp.status_code >= 400:
                logger.error(
                    "Jira API %s: %s",
                    resp.status_code,
                    resp.text,
                )
            resp.raise_for_status()

        data = resp.json()
        ticket_id = str(data["id"])
        ticket_key = data["key"]
        ticket_url = (
            f"{self.jira_url}/browse/{ticket_key}"
        )

        logger.info(
            "Jira ticket created: %s (%s)",
            ticket_key,
            ticket_url,
        )

        return JiraTicketResponse(
            ticket_id=ticket_id,
            ticket_url=ticket_url,
            ticket_key=ticket_key,
        )

    def delete_issue(self, issue_id: str) -> None:
        """Delete a Jira issue by its ID.

        Args:
            issue_id: Jira issue ID (numeric string).

        Raises:
            httpx.HTTPStatusError: On non-2xx response.
        """
        url = (
            f"{self.jira_url}/rest/api/3/issue/{issue_id}"
        )
        with httpx.Client() as http:
            resp = http.delete(
                url,
                auth=(
                    self.jira_email,
                    self.jira_api_token,
                ),
                headers={"Accept": "application/json"},
                timeout=30.0,
            )
            if resp.status_code >= 400:
                logger.error(
                    "Jira delete API %s: %s",
                    resp.status_code,
                    resp.text,
                )
            resp.raise_for_status()

        logger.info("Jira issue %s deleted", issue_id)

    def format_violation_description(
        self,
        state: ViolationState,
    ) -> str:
        """Format a violation as a Jira description.

        Args:
            state: ViolationState to format.

        Returns:
            Plain-text description string.
        """
        lines = [
            "CloudLine Security Violation",
            "",
            f"Check ID:   {state.check_id}",
            f"Severity:   {state.severity}",
            f"Domain:     {state.domain}",
            f"Resource:   {state.resource_arn}",
            f"Status:     {state.status}",
            f"Reason:     {state.reason}",
            f"Risk Score: {state.risk_score}",
            "",
            f"First Detected: {state.first_detected}",
            f"Last Evaluated: {state.last_evaluated}",
        ]

        if state.remediation_id:
            lines.append(
                f"Remediation ID: {state.remediation_id}"
            )

        if state.compliance:
            lines.append("")
            lines.append("Compliance Frameworks:")
            for fw, controls in state.compliance.items():
                if isinstance(controls, list) and controls:
                    controls_str = ", ".join(
                        str(c) for c in controls
                    )
                    lines.append(
                        f"  {fw}: {controls_str}"
                    )

        return "\n".join(lines)
