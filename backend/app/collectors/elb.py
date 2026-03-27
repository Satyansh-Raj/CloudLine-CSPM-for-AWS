"""ELB (Elastic Load Balancing) collector."""

import logging
from datetime import datetime, timezone

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ELBCollector(BaseCollector):
    """Collects ALB/NLB/GLB load balancers with
    listeners, attributes, and WAF associations."""

    def collect(self) -> tuple[str, dict]:
        elbv2 = self.session.client("elbv2")
        return "elb", {
            "load_balancers": (
                self._get_load_balancers(elbv2)
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        elbv2 = self.session.client("elbv2")
        try:
            resp = elbv2.describe_load_balancers(
                Names=[resource_id]
            )
            lbs = resp.get("LoadBalancers", [])
            if lbs:
                return self._build_lb(elbv2, lbs[0])
        except Exception as e:
            logger.error(
                "ELB describe: %s", e
            )
        return {}

    def _get_load_balancers(
        self, elbv2
    ) -> list[dict]:
        lbs = []
        try:
            paginator = elbv2.get_paginator(
                "describe_load_balancers"
            )
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    lbs.append(
                        self._build_lb(elbv2, lb)
                    )
        except Exception as e:
            logger.error(
                "ELB describe: %s", e
            )
        return lbs

    def _build_lb(
        self, elbv2, lb: dict
    ) -> dict:
        arn = lb.get("LoadBalancerArn", "")
        tags = self._get_tags(elbv2, arn)
        listeners = self._get_listeners(
            elbv2, arn
        )
        attributes = self._get_attributes(
            elbv2, arn
        )
        web_acl_arn = self._get_web_acl_arn(arn)
        azs = self._extract_azs(lb)
        return {
            "load_balancer_name": lb.get(
                "LoadBalancerName", ""
            ),
            "load_balancer_arn": arn,
            "dns_name": lb.get("DNSName", ""),
            "scheme": lb.get(
                "Scheme", "internal"
            ),
            "type": lb.get(
                "Type", "application"
            ),
            "vpc_id": lb.get("VpcId", ""),
            "availability_zones": azs,
            "listeners": listeners,
            "attributes": attributes,
            "web_acl_arn": web_acl_arn,
            "tags": tags,
        }

    def _get_tags(
        self, elbv2, arn: str
    ) -> dict:
        try:
            resp = elbv2.describe_tags(
                ResourceArns=[arn]
            )
            descs = resp.get(
                "TagDescriptions", []
            )
            if descs:
                return {
                    t["Key"]: t["Value"]
                    for t in descs[0].get(
                        "Tags", []
                    )
                }
        except Exception as e:
            logger.error(
                "ELB describe_tags: %s", e
            )
        return {}

    def _get_listeners(
        self, elbv2, lb_arn: str
    ) -> list[dict]:
        listeners = []
        try:
            resp = elbv2.describe_listeners(
                LoadBalancerArn=lb_arn
            )
            for lis in resp.get("Listeners", []):
                listener = self._build_listener(
                    elbv2, lis
                )
                listeners.append(listener)
        except Exception as e:
            logger.error(
                "ELB describe_listeners: %s", e
            )
        return listeners

    def _build_listener(
        self, elbv2, lis: dict
    ) -> dict:
        protocol = lis.get("Protocol", "")
        ssl_policy = lis.get("SslPolicy", "")
        default_actions = [
            {"type": a.get("Type", "")}
            for a in lis.get(
                "DefaultActions", []
            )
        ]
        certs = self._get_listener_certs(
            elbv2, lis
        )
        return {
            "protocol": protocol,
            "ssl_policy": ssl_policy,
            "default_actions": default_actions,
            "certificates": certs,
        }

    def _get_listener_certs(
        self, elbv2, lis: dict
    ) -> list[dict]:
        """Build certificate list with expiry info.

        Uses listener Certificates field, then
        queries ACM for days_until_expiry.
        """
        certs = []
        raw_certs = lis.get("Certificates", [])
        if not raw_certs:
            return certs
        acm = None
        try:
            acm = self.session.client("acm")
        except Exception as e:
            logger.error(
                "ELB ACM client init: %s", e
            )
        for rc in raw_certs:
            cert_arn = rc.get(
                "CertificateArn", ""
            )
            days = self._cert_days_until_expiry(
                acm, cert_arn
            )
            certs.append({
                "certificate_arn": cert_arn,
                "days_until_expiry": days,
            })
        return certs

    @staticmethod
    def _cert_days_until_expiry(
        acm, cert_arn: str
    ) -> int | None:
        """Query ACM for certificate expiry.

        Returns days until expiry or None if
        the certificate cannot be described.
        """
        if not acm or not cert_arn:
            return None
        try:
            resp = acm.describe_certificate(
                CertificateArn=cert_arn
            )
            cert = resp.get("Certificate", {})
            not_after = cert.get("NotAfter")
            if not_after:
                now = datetime.now(timezone.utc)
                delta = not_after - now
                return delta.days
        except Exception as e:
            logger.error(
                "ACM describe_certificate "
                "%s: %s",
                cert_arn,
                e,
            )
        return None

    def _get_attributes(
        self, elbv2, lb_arn: str
    ) -> dict:
        """Fetch LB attributes and return
        normalized dict with boolean values."""
        attrs = {
            "access_logs_s3_enabled": False,
            "deletion_protection_enabled": False,
            "routing_http_drop_invalid_"
            "header_fields_enabled": False,
        }
        try:
            resp = (
                elbv2
                .describe_load_balancer_attributes(
                    LoadBalancerArn=lb_arn
                )
            )
            for a in resp.get("Attributes", []):
                key = a.get("Key", "")
                val = a.get("Value", "false")
                mapped = self._map_attribute(
                    key, val
                )
                if mapped is not None:
                    attrs[mapped[0]] = mapped[1]
        except Exception as e:
            logger.error(
                "ELB describe_attributes: %s", e
            )
        return attrs

    @staticmethod
    def _map_attribute(
        key: str, val: str
    ) -> tuple[str, bool] | None:
        """Map AWS attribute key to normalized
        field name and boolean value."""
        mapping = {
            "access_logs.s3.enabled": (
                "access_logs_s3_enabled"
            ),
            "deletion_protection.enabled": (
                "deletion_protection_enabled"
            ),
            "routing.http"
            ".drop_invalid_header_fields"
            ".enabled": (
                "routing_http_drop_invalid_"
                "header_fields_enabled"
            ),
        }
        if key in mapping:
            return (
                mapping[key],
                val.lower() == "true",
            )
        return None

    def _get_web_acl_arn(
        self, lb_arn: str
    ) -> str | None:
        """Query WAFv2 for WebACL associated
        with this load balancer."""
        try:
            waf = self.session.client("wafv2")
            resp = waf.get_web_acl_for_resource(
                ResourceArn=lb_arn
            )
            acl = resp.get("WebACL", {})
            return acl.get("ARN") or None
        except Exception as e:
            logger.error(
                "WAFv2 get_web_acl for LB "
                "%s: %s",
                lb_arn,
                e,
            )
        return None

    @staticmethod
    def _extract_azs(lb: dict) -> list[str]:
        """Extract availability zone names
        from the describe_load_balancers
        response."""
        azs = lb.get("AvailabilityZones", [])
        return [
            az.get("ZoneName", "")
            for az in azs
            if az.get("ZoneName")
        ]
