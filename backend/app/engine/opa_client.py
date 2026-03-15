"""OPA client factory.

Returns either OPACLIClient (local dev) or
OPAHTTPClient (Docker sidecar) based on OPA_MODE
environment variable.
"""

from app.engine.opa_cli import OPACLIClient
from app.engine.opa_http import OPAHTTPClient

# Union type for dependency injection
OPAClient = OPACLIClient | OPAHTTPClient


def create_opa_client(
    mode: str = "cli",
    opa_binary: str = "opa",
    policy_dir: str = "../policies",
    opa_http_url: str = "http://localhost:9720",
) -> OPAClient:
    """Factory: create the right OPA client.

    Args:
        mode: "cli" for subprocess, "http" for
              OPA sidecar REST API.
        opa_binary: Path to opa binary (cli mode).
        policy_dir: Path to policy dir (cli mode).
        opa_http_url: OPA server URL (http mode).

    Returns:
        An OPACLIClient or OPAHTTPClient instance.

    Example:
        >>> client = create_opa_client(mode="cli")
        >>> isinstance(client, OPACLIClient)
        True
    """
    if mode == "http":
        return OPAHTTPClient(base_url=opa_http_url)
    return OPACLIClient(
        opa_binary=opa_binary,
        policy_dir=policy_dir,
    )
