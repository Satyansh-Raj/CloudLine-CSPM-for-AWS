"""AWS Macie 2 collector.

Collects sensitive-data findings from AWS Macie 2 and
returns a normalized MacieData payload.

Gracefully handles:
- Macie not enabled (status != ENABLED)
- AccessDeniedException (missing IAM permissions)
- Any other boto3 error
"""

import logging

import botocore.exceptions

from app.collectors.base import BaseCollector
from app.models.macie import MacieData, MacieFinding

logger = logging.getLogger(__name__)

# AWS limit: max finding IDs per get_findings call
_BATCH_SIZE = 25
# Finding IDs fetched per list_findings page
_PAGE_SIZE = 50


class MacieCollector(BaseCollector):
    """Collects AWS Macie 2 sensitive-data findings.

    Requires IAM permissions:
        macie2:GetMacieSession
        macie2:ListFindings
        macie2:GetFindings
    """

    def collect(self) -> tuple[str, dict]:
        """Full Macie collection for this region.

        Returns:
            ("macie", MacieData.model_dump())
        """
        macie_data = self._collect_macie_data()
        return "macie", macie_data.model_dump()

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        """Return Macie findings for a specific bucket.

        Args:
            resource_id: S3 bucket name.

        Returns:
            Dict with bucket_name and filtered findings.
        """
        macie_data = self._collect_macie_data()
        finding_ids = set(
            macie_data.by_bucket.get(resource_id, [])
        )
        findings = [
            f.model_dump()
            for f in macie_data.findings
            if f.finding_id in finding_ids
        ]
        return {
            "bucket_name": resource_id,
            "findings": findings,
        }

    # --------------------------------------------------
    # Internal helpers
    # --------------------------------------------------

    def _collect_macie_data(self) -> MacieData:
        """Core collection logic.

        Returns MacieData(enabled=False) if Macie is
        disabled or inaccessible in this region.
        """
        client = self.session.client("macie2")

        if not self._is_macie_enabled(client):
            return MacieData(enabled=False)

        finding_ids = self._list_all_finding_ids(
            client
        )
        if not finding_ids:
            return MacieData(enabled=True)

        findings = self._get_findings_batched(
            client, finding_ids
        )

        by_bucket: dict[str, list[str]] = {}
        for f in findings:
            by_bucket.setdefault(
                f.bucket_name, []
            ).append(f.finding_id)

        return MacieData(
            enabled=True,
            findings=findings,
            by_bucket=by_bucket,
            summary=self._compute_summary(findings),
        )

    def _is_macie_enabled(self, client) -> bool:
        """Return True only when Macie status is ENABLED."""
        try:
            resp = client.get_macie_session()
            return resp.get("status") == "ENABLED"
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "AccessDeniedException",
                "ValidationException",
            ):
                logger.warning(
                    "Macie not accessible (%s): %s",
                    code,
                    e,
                )
            else:
                logger.error(
                    "MacieCollector get_macie_session"
                    " error: %s",
                    e,
                )
            return False
        except Exception as e:
            logger.error(
                "MacieCollector unexpected error"
                " checking session: %s",
                e,
            )
            return False

    def _list_all_finding_ids(
        self, client
    ) -> list[str]:
        """Paginate list_findings to collect all IDs.

        Filters to CLASSIFICATION category only.
        """
        finding_ids: list[str] = []
        kwargs: dict = {
            "findingCriteria": {
                "criterion": {
                    "category": {
                        "eq": ["CLASSIFICATION"]
                    }
                }
            },
            "maxResults": _PAGE_SIZE,
        }
        while True:
            try:
                resp = client.list_findings(**kwargs)
            except Exception as e:
                logger.error(
                    "MacieCollector list_findings"
                    " error: %s",
                    e,
                )
                break
            finding_ids.extend(
                resp.get("findingIds", [])
            )
            next_token = resp.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token
        return finding_ids

    def _get_findings_batched(
        self,
        client,
        finding_ids: list[str],
    ) -> list[MacieFinding]:
        """Fetch finding details in batches of _BATCH_SIZE.

        AWS get_findings accepts at most 25 IDs per call.
        """
        findings: list[MacieFinding] = []
        for i in range(
            0, len(finding_ids), _BATCH_SIZE
        ):
            batch = finding_ids[i : i + _BATCH_SIZE]
            try:
                resp = client.get_findings(
                    findingIds=batch
                )
            except Exception as e:
                logger.error(
                    "MacieCollector get_findings"
                    " batch error: %s",
                    e,
                )
                continue
            for raw in resp.get("findings", []):
                finding = self._parse_finding(raw)
                if finding:
                    findings.append(finding)
        return findings

    @staticmethod
    def _parse_finding(
        raw: dict,
    ) -> MacieFinding | None:
        """Parse a raw Macie API finding dict into
        a MacieFinding model."""
        try:
            resources = raw.get(
                "resourcesAffected", {}
            )
            bucket_name = (
                resources.get("s3Bucket", {})
                .get("name", "")
            )
            severity_label = (
                raw.get("severity", {})
                .get("description", "Low")
            )
            return MacieFinding(
                finding_id=raw["id"],
                type=raw.get("type", ""),
                bucket_name=bucket_name,
                severity=severity_label,
                category=raw.get(
                    "category", "CLASSIFICATION"
                ),
                count=raw.get("count", 1),
                first_observed_at=raw.get(
                    "createdAt", ""
                ),
                last_observed_at=raw.get(
                    "updatedAt"
                ),
                region=raw.get("region", ""),
                account_id=raw.get(
                    "accountId", ""
                ),
                detection_types=(
                    MacieCollector
                    ._extract_detection_types(raw)
                ),
            )
        except (KeyError, TypeError) as e:
            logger.warning(
                "MacieCollector failed to parse"
                " finding: %s",
                e,
            )
            return None

    @staticmethod
    def _extract_detection_types(
        raw: dict,
    ) -> list[str]:
        """Extract specific managed identifier types
        from classificationDetails.result.sensitiveData.

        Returns a flat deduplicated list of detection
        type strings (e.g. "MEDICAL_RECORD_NUMBER").
        """
        try:
            sensitive_data = (
                raw.get("classificationDetails", {})
                .get("result", {})
                .get("sensitiveData", [])
            )
            seen: set[str] = set()
            types: list[str] = []
            for entry in sensitive_data:
                for det in entry.get(
                    "detections", []
                ):
                    dt = det.get("type", "")
                    if dt and dt not in seen:
                        seen.add(dt)
                        types.append(dt)
            return types
        except Exception:
            return []

    @staticmethod
    def _compute_summary(
        findings: list[MacieFinding],
    ) -> dict:
        """Return aggregated counts by severity and
        category."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = (
                by_severity.get(f.severity, 0) + 1
            )
            by_category[f.category] = (
                by_category.get(f.category, 0) + 1
            )
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
        }
