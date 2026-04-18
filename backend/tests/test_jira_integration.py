"""Tests for Jira integration — F8 Batch 18.

Covers:
- JiraTicketRequest / JiraTicketResponse models
- ViolationState with ticket fields (roundtrip)
- JiraClient.create_issue (mocked HTTP)
- JiraClient.format_violation_description
- POST /api/v1/violations/{account_id}/{region}/
  {check_id}/{resource_id}/ticket endpoint

TDD: All tests written before implementation (RED).
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.dependencies import (
    get_settings,
    get_state_manager,
)
from app.main import app
from app.pipeline.models import ViolationState

ACCOUNT = "832843292195"
REGION = "ap-south-1"
CHECK_ID = "ec2_no_open_ssh"
RESOURCE_ID = "arn:aws:ec2:ap-south-1:832843292195:sg/sg-1"

JIRA_URL = "https://example.atlassian.net"
JIRA_EMAIL = "sec@example.com"
JIRA_TOKEN = "test-token-abc123"
JIRA_PROJECT = "SEC"


# ---- helpers -------------------------------------------------


def _make_violation(
    check_id: str = CHECK_ID,
    resource_arn: str = RESOURCE_ID,
    status: str = "alarm",
    severity: str = "critical",
    domain: str = "network",
    ticket_id: str | None = None,
    ticket_url: str | None = None,
) -> ViolationState:
    """Build a ViolationState for testing."""
    return ViolationState(
        pk=f"{ACCOUNT}#{REGION}",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        previous_status="ok",
        severity=severity,
        domain=domain,
        risk_score=75,
        resource_arn=resource_arn,
        reason="Port 22 open to 0.0.0.0/0",
        compliance={
            "cis_aws": ["4.1"],
            "nist_800_53": ["SC-7"],
        },
        remediation_id=check_id,
        first_detected="2026-03-01T10:00:00Z",
        last_evaluated="2026-03-10T12:00:00Z",
        resolved_at=None,
        ticket_id=ticket_id,
        ticket_url=ticket_url,
    )


def _make_state_manager(
    state: ViolationState | None = None,
) -> MagicMock:
    """Return a mock StateManager."""
    mgr = MagicMock()
    mgr.get_state.return_value = state
    mgr.put_state.return_value = True
    return mgr


def _configured_settings() -> Settings:
    """Settings with Jira configured."""
    return Settings(
        aws_region=REGION,
        aws_account_id=ACCOUNT,
        jira_url=JIRA_URL,
        jira_email=JIRA_EMAIL,
        jira_api_token=JIRA_TOKEN,
        jira_project_key=JIRA_PROJECT,
    )


def _unconfigured_settings() -> Settings:
    """Settings with Jira NOT configured."""
    return Settings(
        aws_region=REGION,
        aws_account_id=ACCOUNT,
        jira_url="",
        jira_email="",
        jira_api_token="",
        jira_project_key="",
    )


def _override(
    mgr: MagicMock,
    settings_obj: Settings | None = None,
):
    """Apply FastAPI dependency overrides."""
    app.dependency_overrides[
        get_state_manager
    ] = lambda: mgr
    cfg = settings_obj or _configured_settings()
    app.dependency_overrides[
        get_settings
    ] = lambda: cfg


def _clear():
    """Remove all dependency overrides."""
    app.dependency_overrides.pop(
        get_state_manager, None
    )
    app.dependency_overrides.pop(
        get_settings, None
    )
    # Also clear jira client override if present
    from app.dependencies import get_jira_client
    app.dependency_overrides.pop(
        get_jira_client, None
    )


# ============================================================
# TestJiraModels
# ============================================================


class TestJiraModels:
    """Pydantic model correctness for Jira types."""

    def test_ticket_request_defaults(self):
        """JiraTicketRequest has correct defaults."""
        from app.jira.models import JiraTicketRequest

        req = JiraTicketRequest(
            summary="Test issue",
            description="Test desc",
        )
        assert req.summary == "Test issue"
        assert req.description == "Test desc"
        assert req.issue_type == "Bug"
        assert req.priority == "Medium"
        assert req.labels == []

    def test_ticket_request_custom_values(self):
        """JiraTicketRequest accepts custom values."""
        from app.jira.models import JiraTicketRequest

        req = JiraTicketRequest(
            summary="Critical sec issue",
            description="Detailed desc",
            issue_type="Task",
            priority="Highest",
            labels=["security", "aws"],
        )
        assert req.issue_type == "Task"
        assert req.priority == "Highest"
        assert req.labels == ["security", "aws"]

    def test_ticket_response_creation(self):
        """JiraTicketResponse stores all fields."""
        from app.jira.models import JiraTicketResponse

        resp = JiraTicketResponse(
            ticket_id="10042",
            ticket_url=(
                "https://example.atlassian.net"
                "/browse/SEC-42"
            ),
            ticket_key="SEC-42",
        )
        assert resp.ticket_id == "10042"
        assert resp.ticket_key == "SEC-42"
        assert "SEC-42" in resp.ticket_url

    def test_violation_state_has_ticket_id_field(self):
        """ViolationState accepts ticket_id field."""
        state = _make_violation(
            ticket_id="10042",
            ticket_url=(
                "https://example.atlassian.net"
                "/browse/SEC-42"
            ),
        )
        assert state.ticket_id == "10042"
        assert state.ticket_url is not None
        assert "SEC-42" in state.ticket_url

    def test_violation_state_ticket_fields_default_none(
        self,
    ):
        """ticket_id and ticket_url default to None."""
        state = _make_violation()
        assert state.ticket_id is None
        assert state.ticket_url is None

    def test_violation_state_dynamo_roundtrip_with_ticket(
        self,
    ):
        """ViolationState serialises ticket fields."""
        state = _make_violation(
            ticket_id="99999",
            ticket_url=(
                "https://example.atlassian.net"
                "/browse/SEC-1"
            ),
        )
        dumped = state.model_dump()
        assert dumped["ticket_id"] == "99999"
        assert dumped["ticket_url"] is not None

    def test_violation_state_dynamo_roundtrip_no_ticket(
        self,
    ):
        """Roundtrip without ticket keeps None values."""
        state = _make_violation()
        dumped = state.model_dump()
        assert dumped["ticket_id"] is None
        assert dumped["ticket_url"] is None

    def test_create_ticket_from_violation_model(self):
        """CreateTicketFromViolation is importable."""
        from app.jira.models import (
            CreateTicketFromViolation,
        )

        obj = CreateTicketFromViolation()
        # All fields are optional overrides
        assert obj.summary is None
        assert obj.priority is None
        assert obj.labels == []


# ============================================================
# TestJiraClient
# ============================================================


class TestJiraClient:
    """JiraClient HTTP logic (all calls mocked)."""

    def _make_client(self):
        from app.jira.client import JiraClient

        return JiraClient(
            jira_url=JIRA_URL,
            jira_email=JIRA_EMAIL,
            jira_api_token=JIRA_TOKEN,
        )

    def _mock_success_response(self):
        """Build a mock 201 response from Jira API."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {
            "id": "10042",
            "key": "SEC-42",
            "self": (
                f"{JIRA_URL}/rest/api/3"
                "/issue/10042"
            ),
        }
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_create_issue_returns_ticket_response(self):
        """create_issue returns JiraTicketResponse."""
        from app.jira.models import JiraTicketResponse

        client = self._make_client()
        mock_resp = self._mock_success_response()

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            result = client.create_issue(
                project_key=JIRA_PROJECT,
                summary="SSH port open",
                description="Security issue",
                issue_type="Bug",
                priority="High",
                labels=["security"],
            )

        assert isinstance(result, JiraTicketResponse)
        assert result.ticket_id == "10042"
        assert result.ticket_key == "SEC-42"

    def test_create_issue_ticket_url_contains_key(self):
        """ticket_url includes the browse path."""
        client = self._make_client()
        mock_resp = self._mock_success_response()

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            result = client.create_issue(
                project_key=JIRA_PROJECT,
                summary="Test",
                description="Desc",
                issue_type="Bug",
                priority="Medium",
                labels=[],
            )

        assert "SEC-42" in result.ticket_url
        assert JIRA_URL in result.ticket_url

    def test_create_issue_calls_correct_url(self):
        """POST is made to {jira_url}/rest/api/3/issue."""
        client = self._make_client()
        mock_resp = self._mock_success_response()

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            client.create_issue(
                project_key=JIRA_PROJECT,
                summary="Test",
                description="Desc",
                issue_type="Bug",
                priority="Medium",
                labels=[],
            )

        call_args = mock_post.call_args
        called_url = call_args[0][0]
        assert called_url == (
            f"{JIRA_URL}/rest/api/3/issue"
        )

    def test_create_issue_uses_basic_auth(self):
        """Request uses Basic auth with email+token."""
        client = self._make_client()
        mock_resp = self._mock_success_response()

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            client.create_issue(
                project_key=JIRA_PROJECT,
                summary="Test",
                description="Desc",
                issue_type="Bug",
                priority="Medium",
                labels=[],
            )

        call_kwargs = mock_post.call_args[1]
        assert "auth" in call_kwargs
        auth = call_kwargs["auth"]
        assert auth == (JIRA_EMAIL, JIRA_TOKEN)

    def test_create_issue_with_custom_labels(self):
        """Labels are passed in the request payload."""
        client = self._make_client()
        mock_resp = self._mock_success_response()

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            client.create_issue(
                project_key=JIRA_PROJECT,
                summary="Test",
                description="Desc",
                issue_type="Bug",
                priority="Medium",
                labels=["aws", "critical"],
            )

        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        assert "fields" in payload
        assert payload["fields"]["labels"] == [
            "aws",
            "critical",
        ]

    def test_create_issue_sets_project_key(self):
        """Project key is in the request payload."""
        client = self._make_client()
        mock_resp = self._mock_success_response()

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            client.create_issue(
                project_key="INFRA",
                summary="Test",
                description="Desc",
                issue_type="Bug",
                priority="Medium",
                labels=[],
            )

        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        assert (
            payload["fields"]["project"]["key"]
            == "INFRA"
        )

    def test_create_issue_api_error_raises(self):
        """Jira 400 response raises an exception."""
        import httpx

        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.raise_for_status.side_effect = (
            httpx.HTTPStatusError(
                "Bad Request",
                request=MagicMock(),
                response=mock_resp,
            )
        )

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            with pytest.raises(Exception):
                client.create_issue(
                    project_key=JIRA_PROJECT,
                    summary="Test",
                    description="Desc",
                    issue_type="Bug",
                    priority="Medium",
                    labels=[],
                )

    def test_create_issue_auth_error_raises(self):
        """Jira 401 response raises an exception."""
        import httpx

        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.raise_for_status.side_effect = (
            httpx.HTTPStatusError(
                "Unauthorized",
                request=MagicMock(),
                response=mock_resp,
            )
        )

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = mock_resp
            with pytest.raises(Exception):
                client.create_issue(
                    project_key=JIRA_PROJECT,
                    summary="Test",
                    description="Desc",
                    issue_type="Bug",
                    priority="Medium",
                    labels=[],
                )

    def test_create_issue_connection_error_raises(self):
        """Network failure raises an exception."""
        import httpx

        client = self._make_client()

        with patch("httpx.Client.post") as mock_post:
            mock_post.side_effect = (
                httpx.ConnectError("Connection failed")
            )
            with pytest.raises(Exception):
                client.create_issue(
                    project_key=JIRA_PROJECT,
                    summary="Test",
                    description="Desc",
                    issue_type="Bug",
                    priority="Medium",
                    labels=[],
                )

    def test_format_violation_description_has_check_id(
        self,
    ):
        """Formatted description includes check_id."""
        client = self._make_client()
        state = _make_violation()
        desc = client.format_violation_description(
            state
        )
        assert CHECK_ID in desc

    def test_format_violation_description_has_severity(
        self,
    ):
        """Formatted description includes severity."""
        client = self._make_client()
        state = _make_violation(severity="critical")
        desc = client.format_violation_description(
            state
        )
        assert "critical" in desc.lower()

    def test_format_violation_description_has_domain(
        self,
    ):
        """Formatted description includes domain."""
        client = self._make_client()
        state = _make_violation(domain="network")
        desc = client.format_violation_description(
            state
        )
        assert "network" in desc.lower()

    def test_format_violation_description_has_resource(
        self,
    ):
        """Formatted description includes resource ARN."""
        client = self._make_client()
        state = _make_violation()
        desc = client.format_violation_description(
            state
        )
        assert RESOURCE_ID in desc


# ============================================================
# TestJiraEndpoint
# ============================================================


class TestJiraEndpoint:
    """POST /api/v1/violations/.../ticket endpoint."""

    def _url(
        self,
        account_id: str = ACCOUNT,
        region: str = REGION,
        check_id: str = CHECK_ID,
        resource_id: str = RESOURCE_ID,
    ) -> str:
        return (
            f"/api/v1/violations/{account_id}"
            f"/{region}/{check_id}"
            f"/{resource_id}/ticket"
        )

    def _mock_jira_client(
        self,
        ticket_id: str = "10042",
        ticket_key: str = "SEC-42",
    ) -> MagicMock:
        from app.jira.models import JiraTicketResponse

        client = MagicMock()
        client.create_issue.return_value = (
            JiraTicketResponse(
                ticket_id=ticket_id,
                ticket_url=(
                    f"{JIRA_URL}/browse/{ticket_key}"
                ),
                ticket_key=ticket_key,
            )
        )
        return client

    def _override_jira_client(
        self, jira_client: MagicMock
    ):
        from app.dependencies import get_jira_client

        app.dependency_overrides[
            get_jira_client
        ] = lambda: jira_client

    def teardown_method(self):
        _clear()

    # -- success path ------------------------------------------

    def test_create_ticket_returns_200(self):
        """Successful ticket creation returns 200."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        resp = client.post(self._url())
        assert resp.status_code == 200

    def test_create_ticket_response_shape(self):
        """Response includes ticket_id, ticket_key, url."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        data = client.post(self._url()).json()
        assert "ticket_id" in data
        assert "ticket_key" in data
        assert "ticket_url" in data

    def test_create_ticket_correct_values(self):
        """Response values match mock JiraClient output."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client(
            ticket_id="99999",
            ticket_key="SEC-999",
        )
        self._override_jira_client(jira)

        client = TestClient(app)
        data = client.post(self._url()).json()
        assert data["ticket_id"] == "99999"
        assert data["ticket_key"] == "SEC-999"

    def test_create_ticket_updates_dynamodb(self):
        """StateManager.put_state is called to store ticket info."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(self._url())
        assert mgr.put_state.called

    def test_create_ticket_stored_ticket_id_matches(self):
        """put_state is called with correct ticket_id."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client(
            ticket_id="10042"
        )
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(self._url())

        call_args = mgr.put_state.call_args
        saved_state = call_args[0][0]
        assert saved_state.ticket_id == "10042"

    def test_create_ticket_stored_ticket_url_matches(
        self,
    ):
        """put_state is called with correct ticket_url."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client(
            ticket_key="SEC-42"
        )
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(self._url())

        call_args = mgr.put_state.call_args
        saved_state = call_args[0][0]
        assert "SEC-42" in (saved_state.ticket_url or "")

    # -- error paths -------------------------------------------

    def test_violation_not_found_returns_404(self):
        """Missing violation → 404 Not Found."""
        mgr = _make_state_manager(state=None)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        resp = client.post(self._url())
        assert resp.status_code == 404

    def test_ticket_already_exists_returns_409(self):
        """Duplicate ticket creation → 409 Conflict."""
        state = _make_violation(
            ticket_id="10042",
            ticket_url=(
                f"{JIRA_URL}/browse/SEC-42"
            ),
        )
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        resp = client.post(self._url())
        assert resp.status_code == 409

    def test_ticket_already_exists_returns_existing(
        self,
    ):
        """409 response body contains existing ticket."""
        state = _make_violation(
            ticket_id="10042",
            ticket_url=(
                f"{JIRA_URL}/browse/SEC-42"
            ),
        )
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        resp = client.post(self._url())
        detail = resp.json()["detail"]
        assert "10042" in str(detail)

    def test_jira_not_configured_returns_503(self):
        """Unconfigured Jira → 503 Service Unavailable."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr, _unconfigured_settings())

        # Override jira client with None (not configured)
        from app.dependencies import get_jira_client

        app.dependency_overrides[
            get_jira_client
        ] = lambda: None

        client = TestClient(app)
        resp = client.post(self._url())
        assert resp.status_code == 503

    def test_jira_not_configured_error_message(self):
        """503 response includes helpful error message."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr, _unconfigured_settings())

        from app.dependencies import get_jira_client

        app.dependency_overrides[
            get_jira_client
        ] = lambda: None

        client = TestClient(app)
        resp = client.post(self._url())
        assert resp.status_code == 503
        body = resp.json()
        assert "detail" in body

    # -- path param parsing ------------------------------------

    def test_path_params_custom_account(self):
        """Different account_id is parsed correctly."""
        account = "111122223333"
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        url = self._url(account_id=account)
        client = TestClient(app)
        client.post(url)

        mgr.get_state.assert_called_once()
        call_args = mgr.get_state.call_args
        assert call_args[1]["account_id"] == account

    def test_path_params_custom_region(self):
        """Different region is parsed correctly."""
        region = "us-east-1"
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        url = self._url(region=region)
        client = TestClient(app)
        client.post(url)

        call_args = mgr.get_state.call_args
        assert call_args[1]["region"] == region

    def test_path_params_custom_check_id(self):
        """Different check_id is parsed correctly."""
        chk = "s3_block_public"
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        url = self._url(check_id=chk)
        client = TestClient(app)
        client.post(url)

        call_args = mgr.get_state.call_args
        assert call_args[1]["check_id"] == chk

    # -- optional request body ---------------------------------

    def test_custom_summary_in_body(self):
        """Custom summary from request body is passed."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(
            self._url(),
            json={"summary": "Custom Summary Here"},
        )

        call_args = jira.create_issue.call_args
        assert (
            call_args[1]["summary"]
            == "Custom Summary Here"
        )

    def test_custom_priority_in_body(self):
        """Custom priority from request body is passed."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(
            self._url(),
            json={"priority": "Highest"},
        )

        call_args = jira.create_issue.call_args
        assert call_args[1]["priority"] == "Highest"

    def test_custom_labels_in_body(self):
        """Custom labels from request body are passed."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(
            self._url(),
            json={"labels": ["aws", "prod"]},
        )

        call_args = jira.create_issue.call_args
        assert call_args[1]["labels"] == ["aws", "prod"]

    def test_empty_body_uses_defaults(self):
        """No body → defaults applied to create_issue."""
        state = _make_violation()
        mgr = _make_state_manager(state)
        _override(mgr)
        jira = self._mock_jira_client()
        self._override_jira_client(jira)

        client = TestClient(app)
        client.post(self._url())

        # create_issue should still be called
        assert jira.create_issue.called


# ============================================================
# TestGetJiraClientDependency
# ============================================================


class TestGetJiraClientDependency:
    """get_jira_client dependency injection."""

    def test_returns_none_when_jira_url_empty(self):
        """get_jira_client returns None when unconfigured."""
        from app.dependencies import get_jira_client

        settings_obj = _unconfigured_settings()
        result = get_jira_client(settings_obj)
        assert result is None

    def test_returns_client_when_configured(self):
        """get_jira_client returns JiraClient when set."""
        from app.dependencies import get_jira_client
        from app.jira.client import JiraClient

        settings_obj = _configured_settings()
        result = get_jira_client(settings_obj)
        assert isinstance(result, JiraClient)

    def test_client_has_correct_url(self):
        """Returned JiraClient has the correct jira_url."""
        from app.dependencies import get_jira_client

        settings_obj = _configured_settings()
        result = get_jira_client(settings_obj)
        assert result.jira_url == JIRA_URL

    def test_client_has_correct_email(self):
        """Returned JiraClient has the correct email."""
        from app.dependencies import get_jira_client

        settings_obj = _configured_settings()
        result = get_jira_client(settings_obj)
        assert result.jira_email == JIRA_EMAIL
