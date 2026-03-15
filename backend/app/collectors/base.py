"""Abstract base class for all AWS service collectors."""

import abc
import logging

import boto3
import botocore.exceptions

logger = logging.getLogger(__name__)


class CollectionError(Exception):
    """Raised when a collector encounters a
    non-recoverable error."""


class BaseCollector(abc.ABC):
    """Base class that every service collector must extend.

    Each collector queries one AWS service domain and returns
    a normalized dict matching the unified JSON schema.
    """

    def __init__(self, session: boto3.Session):
        self.session = session

    @abc.abstractmethod
    def collect(self) -> tuple[str, dict]:
        """Full collection for this service.

        Returns:
            A tuple of (key_name, data_dict) where key_name
            is the top-level key in the unified JSON schema
            (e.g. "iam", "s3", "ec2").
        """

    @abc.abstractmethod
    def collect_resource(
        self, resource_id: str
    ) -> dict:
        """Targeted collection for a single resource.

        Used by push-mode (event-driven) pipeline when a
        specific resource change is detected via CloudTrail.

        Args:
            resource_id: The AWS resource identifier.

        Returns:
            A dict with the resource's current state.
        """

    def _safe_call(self, func, *args, **kwargs):
        """Wrap a boto3 call with error handling.

        Returns None on failure. Logs specific
        messages for access denied vs other errors.
        """
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "AccessDenied",
                "AccessDeniedException",
            ):
                logger.warning(
                    "Permission denied in %s — "
                    "check IAM role: %s",
                    self.__class__.__name__,
                    e,
                )
            else:
                logger.error(
                    "Collector %s boto3 error: %s",
                    self.__class__.__name__,
                    e,
                )
            return None
        except Exception as e:
            logger.error(
                "Collector %s error: %s",
                self.__class__.__name__,
                str(e),
            )
            return None
