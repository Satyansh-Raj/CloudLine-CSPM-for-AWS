"""Authentication dependencies."""

from fastapi import Depends, HTTPException
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from app.config import Settings
from app.dependencies import get_settings

bearer = HTTPBearer()


def require_auth(
    creds: HTTPAuthorizationCredentials = Depends(
        bearer
    ),
    settings: Settings = Depends(get_settings),
):
    """Validate Bearer token against API key.

    Rejects requests without a valid API key.
    Swap to Cognito JWT validation later.
    """
    if creds.credentials != settings.api_key:
        raise HTTPException(
            status_code=403, detail="Forbidden"
        )
    return creds.credentials
