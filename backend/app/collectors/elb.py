"""ELB (Elastic Load Balancing) collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ELBCollector(BaseCollector):
    """Collects ALB/NLB/GLB load balancers."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("elbv2")
        return "elb", {
            "load_balancers": (
                self._get_load_balancers(client)
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("elbv2")
        try:
            resp = client.describe_load_balancers(
                Names=[resource_id]
            )
            lbs = resp.get("LoadBalancers", [])
            if lbs:
                return self._build_lb(lbs[0])
        except Exception as e:
            logger.error(
                "ELB describe: %s", e
            )
        return {}

    def _get_load_balancers(
        self, client
    ) -> list[dict]:
        lbs = []
        try:
            paginator = client.get_paginator(
                "describe_load_balancers"
            )
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    lbs.append(
                        self._build_lb(lb)
                    )
        except Exception as e:
            logger.error(
                "ELB describe: %s", e
            )
        return lbs

    def _build_lb(self, lb: dict) -> dict:
        tags = {}
        return {
            "lb_name": lb.get(
                "LoadBalancerName", ""
            ),
            "arn": lb.get(
                "LoadBalancerArn", ""
            ),
            "dns_name": lb.get("DNSName", ""),
            "scheme": lb.get(
                "Scheme", "internal"
            ),
            "lb_type": lb.get("Type", "application"),
            "vpc_id": lb.get("VpcId", ""),
            "tags": tags,
        }
