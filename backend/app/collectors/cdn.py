"""CloudFront and Route53 collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class CDNCollector(BaseCollector):
    """Collects CloudFront distributions and
    Route53 hosted zones."""

    def collect(self) -> tuple[str, dict]:
        return "cdn", {
            "distributions": (
                self._get_distributions()
            ),
            "hosted_zones": (
                self._get_hosted_zones()
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        if resource_id.startswith("E"):
            dists = self._get_distributions(
                resource_id
            )
            return dists[0] if dists else {}
        return {}

    def _get_distributions(
        self, dist_id: str | None = None
    ) -> list[dict]:
        dists = []
        try:
            client = self.session.client(
                "cloudfront"
            )
            if dist_id:
                resp = client.get_distribution(
                    Id=dist_id
                )
                d = resp["Distribution"]
                cfg = d.get(
                    "DistributionConfig", {}
                )
                dists.append(
                    {
                        "distribution_id": d["Id"],
                        "arn": d.get("ARN", ""),
                        "domain_name": d.get(
                            "DomainName", ""
                        ),
                        "enabled": cfg.get(
                            "Enabled", True
                        ),
                    }
                )
            else:
                resp = (
                    client.list_distributions()
                )
                items = (
                    resp.get(
                        "DistributionList", {}
                    ).get("Items", [])
                )
                for d in items:
                    dists.append(
                        {
                            "distribution_id": d[
                                "Id"
                            ],
                            "arn": d.get(
                                "ARN", ""
                            ),
                            "domain_name": d.get(
                                "DomainName", ""
                            ),
                            "enabled": d.get(
                                "Enabled", True
                            ),
                        }
                    )
        except Exception as e:
            logger.error(
                "CloudFront: %s", e
            )
        return dists

    def _get_hosted_zones(self) -> list[dict]:
        zones = []
        try:
            client = self.session.client(
                "route53"
            )
            resp = client.list_hosted_zones()
            for z in resp.get(
                "HostedZones", []
            ):
                zone_id = z["Id"].split("/")[-1]
                zones.append(
                    {
                        "hosted_zone_id": zone_id,
                        "name": z.get(
                            "Name", ""
                        ).rstrip("."),
                        "is_private": z.get(
                            "Config", {}
                        ).get(
                            "PrivateZone", False
                        ),
                        "record_count": z.get(
                            "ResourceRecordSetCount",
                            0,
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Route53: %s", e
            )
        return zones
