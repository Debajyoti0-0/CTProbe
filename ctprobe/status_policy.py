"""HTTP status-code parsing and centralized response classification."""

import re
from dataclasses import dataclass
from typing import FrozenSet, Optional

from .models import ErrorType


DEFAULT_MATCH_CODES = frozenset(
    set(range(200, 300)) | {301, 302, 307, 401, 403, 405, 500}
)
_STATUS_TOKEN = re.compile(r"^(\d{3})(?:-(\d{3}))?$")


def format_status_codes(codes: FrozenSet[int]) -> str:
    """Format status codes as deterministic comma-separated values and ranges."""
    if not codes:
        return "NONE"

    values = sorted(codes)
    ranges = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append((start, previous))
        start = previous = value
    ranges.append((start, previous))

    formatted = []
    for start, end in ranges:
        formatted.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(formatted)


class StatusCodeError(ValueError):
    """Raised when a status-code expression is invalid."""


def parse_status_codes(expression: str) -> FrozenSet[int]:
    """Parse status codes, ranges, or ``all`` into a set of 100-599 codes."""
    if expression is None:
        raise StatusCodeError("status-code expression is required")

    value = expression.strip().lower()
    if value == "all":
        return frozenset(range(100, 600))
    if not value:
        raise StatusCodeError("status-code expression cannot be empty")

    codes = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            raise StatusCodeError(
                f"invalid status-code expression {expression!r}: empty item"
            )
        match = _STATUS_TOKEN.fullmatch(token)
        if not match:
            raise StatusCodeError(f"invalid status code or range: {token!r}")
        start = int(match.group(1))
        end = int(match.group(2) or match.group(1))
        if not 100 <= start <= 599 or not 100 <= end <= 599:
            raise StatusCodeError(f"status codes must be between 100 and 599: {token!r}")
        if end < start:
            raise StatusCodeError(f"status range is reversed: {token!r}")
        codes.update(range(start, end + 1))
    return frozenset(codes)


@dataclass(frozen=True)
class Classification:
    """Canonical classification of one HTTP attempt."""
    network_reachable: bool
    http_response_received: bool
    status_matched: bool
    status_filtered: bool
    live: bool
    error_type: Optional[ErrorType] = None


def classify_response(
    status_code: Optional[int],
    match_codes: FrozenSet[int],
    filter_codes: FrozenSet[int],
    error_type: Optional[ErrorType] = None,
) -> Classification:
    """Classify a response without duplicating policy in workers or exporters."""
    received = status_code is not None
    if not received:
        return Classification(
            network_reachable=False,
            http_response_received=False,
            status_matched=False,
            status_filtered=False,
            live=False,
            error_type=error_type or ErrorType.UNKNOWN_ERROR,
        )

    filtered = status_code in filter_codes
    matched = status_code in match_codes and not filtered
    return Classification(
        network_reachable=True,
        http_response_received=True,
        status_matched=matched,
        status_filtered=filtered,
        live=matched,
    )
