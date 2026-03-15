"""OPA HTTP client for Docker sidecar mode.

Communicates with OPA server via its REST API.
Used when OPA runs as a sidecar container.
"""

import logging

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0


class OPAHTTPClient:
    """Evaluates Rego policies via OPA REST API.

    Note: Uses synchronous httpx. FastAPI dispatches
    sync endpoints to thread-pool workers, so this
    does not block the event loop. Convert to
    httpx.AsyncClient if callers become async.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:9720",
    ):
        self.base_url = base_url.rstrip("/")

    def evaluate(
        self,
        input_data: dict,
        query: str,
    ) -> list[dict]:
        """Evaluate a Rego query against input.

        Args:
            input_data: The unified JSON document.
            query: Rego query string, e.g.
                   "data.aws.identity.iam
                   .violations"

        Returns:
            List of result objects from OPA.
        """
        path = self._query_to_path(query)
        url = f"{self.base_url}/v1/{path}"

        try:
            resp = httpx.post(
                url,
                json={"input": input_data},
                timeout=DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json().get("result", [])
            if isinstance(result, list):
                return result
            if isinstance(result, set):
                return list(result)
            if isinstance(result, dict):
                return [result]
            return []
        except httpx.TimeoutException:
            logger.error("OPA HTTP request timed out")
            return []
        except httpx.HTTPStatusError as e:
            logger.error(
                "OPA HTTP error %s: %s",
                e.response.status_code,
                e.response.text,
            )
            return []
        except Exception as e:
            logger.error("OPA HTTP error: %s", e)
            return []

    def evaluate_all(
        self,
        input_data: dict,
    ) -> dict[str, list[dict]]:
        """Evaluate all policies under data.aws.

        Args:
            input_data: The unified JSON document.

        Returns:
            Dict mapping package paths to their
            violation/compliant results.
        """
        url = f"{self.base_url}/v1/data/aws"

        try:
            resp = httpx.post(
                url,
                json={"input": input_data},
                timeout=60.0,
            )
            resp.raise_for_status()
            raw = resp.json().get("result", {})
            return self._extract_packages(raw)
        except httpx.TimeoutException:
            logger.error(
                "OPA HTTP eval_all timed out"
            )
            return {}
        except httpx.HTTPStatusError as e:
            logger.error(
                "OPA HTTP eval_all error %s: %s",
                e.response.status_code,
                e.response.text,
            )
            return {}
        except Exception as e:
            logger.error(
                "OPA HTTP eval_all error: %s", e
            )
            return {}

    def _extract_packages(
        self, raw: dict
    ) -> dict[str, dict]:
        """Extract package results from OPA response.

        Handles nested package structures like
        data.aws.identity.iam where violations
        are 2 levels deep.

        Args:
            raw: The 'result' dict from OPA response.

        Returns:
            Dict mapping package names to
            violations/compliant lists.
        """
        results = {}
        self._walk_packages(raw, "", results)
        return results

    def _walk_packages(
        self,
        node: dict,
        prefix: str,
        results: dict,
    ) -> None:
        """Recursively find packages with violations."""
        for key, value in node.items():
            if not isinstance(value, dict):
                continue
            path = (
                f"{prefix}.{key}" if prefix else key
            )
            violations = value.get("violations", [])
            compliant = value.get("compliant", [])
            if violations or compliant:
                results[path] = {
                    "violations": (
                        list(violations)
                        if isinstance(
                            violations,
                            (list, set),
                        )
                        else []
                    ),
                    "compliant": (
                        list(compliant)
                        if isinstance(
                            compliant,
                            (list, set),
                        )
                        else []
                    ),
                }
            else:
                self._walk_packages(
                    value, path, results
                )

    def _query_to_path(self, query: str) -> str:
        """Convert Rego query to OPA REST API path.

        Args:
            query: e.g. "data.aws.identity.iam.violations"

        Returns:
            API path e.g. "data/aws/identity/iam/violations"

        Example:
            >>> c = OPAHTTPClient()
            >>> c._query_to_path("data.aws.identity.iam")
            'data/aws/identity/iam'
        """
        return query.replace(".", "/")
