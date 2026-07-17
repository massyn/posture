"""Exception taxonomy for posture collectors.

Every exception carries structured attributes so wrapper scripts can compose
alerts from fields, never by parsing message strings. Exceptions propagate;
posture never swallows and continues.
"""

from __future__ import annotations


class PostureError(Exception):
    """Base class for all posture exceptions."""

    def __init__(self, message: str, *, source: str | None = None) -> None:
        super().__init__(message)
        self.source = source


class AuthenticationError(PostureError):
    """Raised when a collector fails to authenticate with its source."""

    def __init__(
        self, message: str, *, source: str | None = None, hint: str | None = None
    ) -> None:
        super().__init__(message, source=source)
        self.hint = hint


class RateLimitExhausted(PostureError):
    """Raised when retries against a rate limit are exhausted."""

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
        resource: str | None = None,
        records_so_far: int = 0,
    ) -> None:
        super().__init__(message, source=source)
        self.resource = resource
        self.records_so_far = records_so_far


class ResourceUnknown(PostureError):
    """Raised when a requested resource is not in the collector's manifest."""

    def __init__(
        self, message: str, *, source: str | None = None, resource: str | None = None
    ) -> None:
        super().__init__(message, source=source)
        self.resource = resource


class IncompleteCollection(PostureError):
    """Raised when a pull dies mid-pagination after retries are exhausted.

    Partial data does not exist in this library's vocabulary — a partial
    snapshot presented as complete is a compliance lie. Callers must treat
    this as "no data", not "some data".
    """

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
        resource: str | None = None,
        records_so_far: int = 0,
    ) -> None:
        super().__init__(message, source=source)
        self.resource = resource
        self.records_so_far = records_so_far
