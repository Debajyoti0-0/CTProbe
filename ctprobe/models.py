"""Result models and data structures."""

from dataclasses import dataclass, field
from typing import Optional, List, Union
from enum import Enum


class LiveStatus(Enum):
    """Live status of a tested subdomain."""
    LIVE = "live"
    DEAD = "dead"
    NOT_TESTED = "not_tested"


class ErrorType(Enum):
    """Categorized error types."""
    DNS_ERROR = "dns_error"
    CONNECTION_ERROR = "connection_error"
    CONNECTION_TIMEOUT = "connection_timeout"
    TLS_ERROR = "tls_error"
    HTTP_429 = "http_429"
    HTTP_5XX = "http_5xx"
    HTTP_ERROR = "http_error"
    PROXY_ERROR = "proxy_error"
    PROTOCOL_ERROR = "protocol_error"
    RATE_LIMITED = "rate_limited"
    INVALID_URL = "invalid_url"
    UNKNOWN_ERROR = "unknown_error"


class ThreatLevel(Enum):
    """Threat level classification."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class LiveTestResult:
    """Result of testing a single discovered subdomain for reachability."""
    domain: str
    live: bool
    attempted_url: Optional[str] = None
    network_reachable: bool = False
    http_response_received: bool = False
    status_matched: bool = False
    status_filtered: bool = False
    status_code: Optional[int] = None
    scheme: Optional[str] = None
    final_url: Optional[str] = None
    http_version: Optional[str] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    error_type: Optional[ErrorType] = None
    redirect_count: int = 0
    server: Optional[str] = None
    content_type: Optional[str] = None
    timestamp: Optional[str] = None

    # Threat analysis fields
    threat_score: int = 0
    threat_level: ThreatLevel = ThreatLevel.NONE
    threat_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary, handling enums."""
        result = {
            "domain": self.domain,
            "live": self.live,
            "attempted_url": self.attempted_url,
            "network_reachable": self.network_reachable,
            "http_response_received": self.http_response_received,
            "status_code": self.status_code,
            "status_matched": self.status_matched,
            "status_filtered": self.status_filtered,
            "scheme": self.scheme,
            "final_url": self.final_url,
            "http_version": self.http_version,
            "response_time_ms": self.response_time_ms,
            "error": self.error,
            "error_type": self.error_type.value if self.error_type else None,
            "redirect_count": self.redirect_count,
            "server": self.server,
            "content_type": self.content_type,
            "timestamp": self.timestamp,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level.value,
            "threat_indicators": self.threat_indicators,
        }
        return result


@dataclass
class ScanConfig:
    """Configuration for a scan session."""
    target_domain: Optional[str]
    perform_live_test: bool = False
    live_mode: Optional[bool] = None
    match_code_requested: bool = False
    filter_code_requested: bool = False
    match_code_expression: Optional[str] = None
    filter_code_expression: Optional[str] = None
    http_version: str = "auto"
    workers: int = 30
    timeout: float = 10.0
    proxy: Optional[str] = None
    # None (disabled), True (bare --tor, default endpoint), or an explicit
    # endpoint string — mirrors build_network_config(tor=...).
    tor: Optional[Union[bool, str]] = None
    bypass_tls: bool = False
    stealth: bool = False
    stealth_min_delay: float = 1.0
    stealth_max_delay: float = 3.0
    threat_analysis: bool = False
    output_format: str = "txt"
    output_dir: str = "Outputs"
    custom_filename: Optional[str] = None
    force: bool = False
    verbose: bool = False
    debug: bool = False
    quiet: bool = False
    no_color: bool = False
    headers: dict = field(default_factory=dict)
    user_agent: str = "Mozilla/5.0"
    match_codes: frozenset = field(
        default_factory=lambda: frozenset(set(range(200, 300)) | {301, 302, 307, 401, 403, 405, 500})
    )
    filter_codes: frozenset = field(default_factory=lambda: frozenset())


@dataclass
class ScanSummary:
    """Summary statistics for a complete scan."""
    target_domain: str
    discovered_count: int
    tested_count: int = 0
    live_count: int = 0
    failed_count: int = 0
    retry_count: int = 0
    rate_limited_responses: int = 0
    duration_seconds: float = 0.0
    live_testing_performed: bool = False


@dataclass
class DiscoveryResult:
    """Outcome of a Certificate Transparency discovery request.

    ``domains`` holds the raw certificate DNS names returned by the CT
    source; they are not yet filtered to the target apex.
    """
    success: bool
    domains: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    error: Optional[str] = None
    raw_count: int = 0
