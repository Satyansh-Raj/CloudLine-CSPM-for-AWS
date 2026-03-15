"""OPA CLI subprocess client.

Calls `opa eval` to evaluate Rego policies against
input data. Used for local development without Docker.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class OPACLIClient:
    """Evaluates Rego policies via `opa eval` CLI."""

    def __init__(
        self,
        opa_binary: str = "opa",
        policy_dir: str = "../policies",
    ):
        self.opa_binary = opa_binary
        self.policy_dir = str(
            Path(policy_dir).resolve()
        )

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
        input_json = json.dumps(input_data)
        if len(input_json) > 10 * 1024 * 1024:
            logger.warning(
                "OPA input size %d bytes — "
                "consider opa_mode=http",
                len(input_json),
            )

        try:
            cmd = [
                self.opa_binary,
                "eval",
                "-d",
                self.policy_dir,
                "--stdin-input",
                query,
                "--format",
                "json",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                input=input_json,
                timeout=30,
            )

            if result.returncode != 0:
                logger.error(
                    "OPA eval failed: %s",
                    result.stderr,
                )
                return []

            return self._parse_output(
                result.stdout
            )

        except subprocess.TimeoutExpired:
            logger.error("OPA eval timed out")
            return []
        except Exception as e:
            logger.error("OPA eval error: %s", e)
            return []

    def evaluate_all(
        self,
        input_data: dict,
    ) -> dict[str, list[dict]]:
        """Evaluate all policies and return results
        keyed by package name.

        Args:
            input_data: The unified JSON document.

        Returns:
            Dict mapping package paths to their
            violation/compliant results.
        """
        input_json = json.dumps(input_data)

        try:
            cmd = [
                self.opa_binary,
                "eval",
                "-d",
                self.policy_dir,
                "--stdin-input",
                "data.aws",
                "--format",
                "json",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                input=input_json,
                timeout=60,
            )

            if result.returncode != 0:
                logger.error(
                    "OPA eval all failed: %s",
                    result.stderr,
                )
                return {}

            output = json.loads(result.stdout)
            return self._extract_packages(output)

        except Exception as e:
            logger.error(
                "OPA eval all error: %s", e
            )
            return {}

    def _extract_packages(
        self, output: dict
    ) -> dict[str, dict]:
        """Extract package results from OPA output.

        Handles nested package structures like
        data.aws.identity.iam where violations
        are 2 levels deep.

        Args:
            output: Parsed OPA JSON response.

        Returns:
            Dict mapping package names to
            violations/compliant lists.
        """
        results = {}
        raw = (
            output.get("result", [{}])[0]
            .get("expressions", [{}])[0]
            .get("value", {})
        )
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

    def _parse_output(
        self, stdout: str
    ) -> list[dict]:
        """Parse OPA JSON output into result list.

        Args:
            stdout: Raw OPA stdout string.

        Returns:
            List of result dicts.
        """
        try:
            output = json.loads(stdout)
            value = (
                output.get("result", [{}])[0]
                .get("expressions", [{}])[0]
                .get("value", [])
            )
            if isinstance(value, list):
                return value
            if isinstance(value, set):
                return list(value)
            if isinstance(value, dict):
                return [value]
            return []
        except (json.JSONDecodeError, IndexError):
            return []
