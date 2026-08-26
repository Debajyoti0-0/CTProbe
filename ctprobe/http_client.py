"""HTTP client abstraction supporting multiple protocol versions."""

import os
import time
import subprocess
import shutil
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import requests

from .models import ErrorType
from .logging_utils import Logger


class HTTPClientError(Exception):
    """HTTP client error carrying a structured :class:`ErrorType`."""

    def __init__(self, message: str, error_type: ErrorType = ErrorType.UNKNOWN_ERROR):
        super().__init__(message)
        self.error_type = error_type


@lru_cache(maxsize=1)
def _httpx_http2_available() -> bool:
    """Whether httpx AND its HTTP/2 backend (h2) are importable. Cached once."""
    if find_spec_missing("httpx"):
        return False
    return not find_spec_missing("h2")


def find_spec_missing(name: str) -> bool:
    from importlib.util import find_spec
    try:
        return find_spec(name) is None
    except (ImportError, ValueError):
        return True


@lru_cache(maxsize=1)
def _curl_http3_available() -> bool:
    """Whether a curl binary with genuine HTTP/3 support is present. Cached once."""
    curl_path = shutil.which("curl")
    if not curl_path:
        return False
    try:
        result = subprocess.run(
            [curl_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "http3" in result.stdout.lower()


def check_protocol_capability(http_version: str) -> Tuple[bool, str]:
    """Report whether an explicit protocol version can actually run.

    Used for a single startup pre-flight check when ``--force`` is set, so the
    error is surfaced once rather than per domain.
    """
    if http_version == "2":
        return (_httpx_http2_available(), "httpx[http2] is not installed")
    if http_version == "3":
        return (_curl_http3_available(), "curl with HTTP/3 support is not available")
    return (True, "")


def resolve_headers(base_headers: Dict[str, str], user_agent: str) -> Dict[str, str]:
    """Merge the configured User-Agent into headers with one defined precedence.

    An explicit ``--header "User-Agent: ..."`` (matched case-insensitively) always
    wins; otherwise the ``--user-agent`` value is used. A User-Agent is always
    present, and a duplicate UA header is never emitted. This is the single source
    of truth shared by every request path (threaded HTTP/1.1/2/3 and async) so the
    same invocation cannot send different User-Agents on different engines.
    """
    headers = dict(base_headers)
    if not any(name.lower() == "user-agent" for name in headers):
        headers["User-Agent"] = user_agent
    return headers


class HTTPClient:
    """Unified HTTP client supporting HTTP/1.1, HTTP/2, and HTTP/3."""

    #: Maximum redirects followed per request; kept in sync with the async engine.
    MAX_REDIRECTS = 10

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0",
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        bypass_tls: bool = False,
        logger: Optional[Logger] = None,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.headers = headers or {}
        self.proxies = proxies
        self.bypass_tls = bypass_tls
        self.logger = logger or Logger()

    def request(
        self,
        url: str,
        http_version: str = "auto",
        force: bool = False,
        method: str = "GET",
    ) -> Dict[str, Any]:
        """
        Make an HTTP request with capability-aware protocol negotiation.

        ``force`` disables HTTP *version* fallback only. In ``auto`` mode a
        protocol is attempted only when it is actually available (detected once
        and cached), so a missing curl/HTTP-3 never spawns a subprocess per call.

        Raises:
            HTTPClientError: On all request failures.
        """
        if http_version not in ("auto", "1.1", "2", "3"):
            raise HTTPClientError(f"Unknown HTTP version: {http_version}")

        candidates = self._protocol_order(http_version, force)
        errors: List[str] = []
        last_exc: Optional[HTTPClientError] = None
        for version in candidates:
            available, reason = self._protocol_available(version)
            if not available:
                errors.append(f"HTTP/{version}: {reason}")
                if force:
                    raise HTTPClientError(
                        f"HTTP/{version} was explicitly forced but is unavailable: {reason}",
                        ErrorType.PROTOCOL_ERROR,
                    )
                continue
            try:
                result = self._dispatch(version, url, method)
                # Fail-closed on a forced version: never accept a silently
                # downgraded protocol (e.g. httpx negotiating HTTP/1.1 for a
                # forced HTTP/2). The actual negotiated version is authoritative.
                if force:
                    self._enforce_forced_version(version, result.get("http_version"))
                return result
            except HTTPClientError as exc:
                errors.append(f"HTTP/{version}: {exc}")
                last_exc = exc
                if force:
                    raise
        # Preserve the last transport error type (TLS/timeout/DNS/...) rather than
        # masking it as a generic protocol error.
        final_type = last_exc.error_type if last_exc else ErrorType.PROTOCOL_ERROR
        raise HTTPClientError("All protocols failed: " + " | ".join(errors), final_type)

    @staticmethod
    def _protocol_order(http_version: str, force: bool) -> List[str]:
        """Ordered protocol candidates for a version selection."""
        base = {
            "auto": ["3", "2", "1.1"],
            "3": ["3", "2", "1.1"],
            "2": ["2", "1.1"],
            "1.1": ["1.1"],
        }[http_version]
        # Force pins to the selected version (no version fallback). In auto mode
        # force is rejected at the CLI, so this only affects explicit versions.
        if force and http_version != "auto":
            return base[:1]
        return base

    @staticmethod
    def _protocol_available(version: str) -> Tuple[bool, str]:
        if version == "3":
            return (_curl_http3_available(), "curl with HTTP/3 support is not available")
        if version == "2":
            return (_httpx_http2_available(), "httpx[http2] is not installed")
        return (True, "")

    def _dispatch(self, version: str, url: str, method: str) -> Dict[str, Any]:
        if version == "3":
            return self._request_http3(url, method)
        if version == "2":
            return self._request_http2(url, method)
        return self._request_http11(url, method)

    @staticmethod
    def _enforce_forced_version(version: str, negotiated: Optional[str]) -> None:
        """Reject a silently downgraded protocol when a version was forced.

        ``--force`` must never accept a protocol other than the one requested
        (spec §19). httpx may negotiate HTTP/1.1 even with ``http2=True``; if the
        wire version does not match the forced request, fail closed rather than
        report a lie.
        """
        expected = {"1.1": "HTTP/1.1", "2": "HTTP/2", "3": "HTTP/3"}.get(version)
        if expected is not None and negotiated != expected:
            raise HTTPClientError(
                f"HTTP/{version} was forced but the server negotiated "
                f"{negotiated or 'an unknown version'}",
                ErrorType.PROTOCOL_ERROR,
            )

    def _request_http11(self, url: str, method: str = "GET") -> Dict[str, Any]:
        """Make HTTP/1.1 request using requests library."""
        session = requests.Session()

        # Unified User-Agent precedence (explicit --header wins), shared by every
        # engine so the UA never differs across HTTP versions.
        headers = resolve_headers(self.headers, self.user_agent)

        try:
            response = session.request(
                method,
                url,
                headers=headers,
                proxies=self.proxies,
                verify=not self.bypass_tls,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )
            # Bound body consumption: we only need status/headers, never the body.
            response.close()

            return {
                "status_code": response.status_code,
                "final_url": str(response.url),
                "http_version": "HTTP/1.1",
                "headers": dict(response.headers),
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "server": response.headers.get("server"),
                "content_type": response.headers.get("content-type"),
                "redirect_count": len(response.history),
            }
        except requests.exceptions.Timeout:
            raise HTTPClientError("Timeout", ErrorType.CONNECTION_TIMEOUT)
        except requests.exceptions.ProxyError as exc:
            raise HTTPClientError(f"Proxy error: {exc}", ErrorType.PROXY_ERROR)
        except requests.exceptions.SSLError as exc:
            raise HTTPClientError(f"TLS error: {exc}", ErrorType.TLS_ERROR)
        except requests.exceptions.ConnectionError as exc:
            message = str(exc).lower()
            if any(token in message for token in (
                "name or service not known", "nodename nor servname",
                "name resolution", "getaddrinfo", "temporary failure in name",
            )):
                raise HTTPClientError(f"DNS error: {exc}", ErrorType.DNS_ERROR)
            raise HTTPClientError(f"Connection error: {exc}", ErrorType.CONNECTION_ERROR)
        except requests.exceptions.RequestException as exc:
            raise HTTPClientError(f"Request failed: {exc}", ErrorType.UNKNOWN_ERROR)
        finally:
            session.close()
    
    def _request_http2(self, url: str, method: str = "GET") -> Dict[str, Any]:
        """Make HTTP/2 request using httpx library."""
        try:
            import httpx
        except ImportError as exc:
            raise HTTPClientError(
                "HTTP/2 requires httpx. Install with: pip install 'httpx[http2]'",
                ErrorType.PROTOCOL_ERROR,
            ) from exc

        headers = resolve_headers(self.headers, self.user_agent)

        # httpx accepts a single proxy URL; both schemes share one endpoint here.
        proxy = None
        if self.proxies:
            proxy = self.proxies.get("https") or self.proxies.get("http")

        try:
            start_time = time.monotonic()

            with httpx.Client(
                http2=True,
                verify=not self.bypass_tls,
                headers=headers,
                proxy=proxy,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                # stream() sends the request and receives status/headers without
                # downloading the body: we only need metadata (spec §36), and
                # http2=True may still negotiate HTTP/1.1, so the reported version
                # must come from the wire, never the request (spec §28/§94).
                with client.stream(method, url) as response:
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    return {
                        "status_code": response.status_code,
                        "final_url": str(response.url),
                        "http_version": response.http_version,
                        "headers": dict(response.headers),
                        "response_time_ms": elapsed_ms,
                        "server": response.headers.get("server"),
                        "content_type": response.headers.get("content-type"),
                        "redirect_count": len(response.history),
                    }
        except HTTPClientError:
            raise
        except Exception as exc:
            raise HTTPClientError(f"HTTP/2 failed: {exc}", ErrorType.PROTOCOL_ERROR)
    
    def _request_http3(self, url: str, method: str = "GET") -> Dict[str, Any]:
        """Make HTTP/3 request using curl subprocess."""
        curl_path = shutil.which("curl")
        
        if not curl_path:
            raise HTTPClientError(
                "HTTP/3 requires curl with HTTP/3 support"
            )
        
        # Discard the response body to os.devnull: like the other engines we only
        # need status/timing/redirect metadata, never the body (Phase 28/47). This
        # also keeps stdout limited to the -w trailer, so parsing can't be confused
        # by body content that happens to look like a status line.
        command = [
            curl_path,
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs", str(self.MAX_REDIRECTS),
            "--max-time", str(int(self.timeout + 1)),
            "--http3-only",
            "--output", os.devnull,
            "-X", method,
            "-w", "%{http_code}\n%{time_total}\n%{num_redirects}\n%{url_effective}",
        ]

        # Add headers. Merge the User-Agent through the shared resolver (explicit
        # --header wins) and emit it as one --header, rather than adding a separate
        # --user-agent that curl would let a --header override anyway — this keeps
        # the negotiated UA identical to the other engines and avoids duplicates.
        for key, value in resolve_headers(self.headers, self.user_agent).items():
            command.extend(["--header", f"{key}: {value}"])

        if self.bypass_tls:
            command.append("--insecure")

        # Proxy (curl accepts a single --proxy URL)
        if self.proxies:
            proxy_url = self.proxies.get("https") or self.proxies.get("http")
            if proxy_url:
                command.extend(["--proxy", proxy_url])

        # End of options: a discovered SAN entry that begins with "-" must never be
        # interpreted by curl as a flag (argument-injection defense, Phase 46). The
        # caller always prefixes a scheme, so this is defense-in-depth.
        command.extend(["--", url])

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
            )

            if result.returncode != 0:
                raise HTTPClientError(f"curl failed: {result.stderr.strip()}")

            # stdout now holds only the -w trailer: status, time, redirects, url.
            lines = result.stdout.strip().split("\n")
            if len(lines) < 4:
                raise HTTPClientError("Invalid curl response format")

            try:
                status_code = int(lines[0])
                response_time = float(lines[1])
                redirect_count = int(lines[2])
            except (ValueError, IndexError):
                raise HTTPClientError("Could not parse curl response")

            # Report the actually-followed final URL, not the requested one.
            final_url = lines[3].strip() or url

            return {
                "status_code": status_code,
                "final_url": final_url,
                "http_version": "HTTP/3",
                "headers": {},
                "response_time_ms": response_time * 1000,
                "server": None,
                "content_type": None,
                "redirect_count": redirect_count,
            }
        except subprocess.TimeoutExpired:
            raise HTTPClientError("HTTP/3 timeout", ErrorType.CONNECTION_TIMEOUT)
        except HTTPClientError:
            raise
        except Exception as exc:
            raise HTTPClientError(f"HTTP/3 error: {exc}", ErrorType.PROTOCOL_ERROR)

    @staticmethod
    def classify_error(error_msg: str) -> ErrorType:
        """Classify an error message."""
        msg = error_msg.lower()
        
        if "timeout" in msg:
            return ErrorType.CONNECTION_TIMEOUT
        elif "dns" in msg or "name resolution" in msg:
            return ErrorType.DNS_ERROR
        elif "connection" in msg or "refused" in msg:
            return ErrorType.CONNECTION_ERROR
        elif "tls" in msg or "ssl" in msg or "certificate" in msg:
            return ErrorType.TLS_ERROR
        elif "429" in msg:
            return ErrorType.HTTP_429
        elif "5" in msg and "0" in msg:
            return ErrorType.HTTP_5XX
        elif "proxy" in msg or "socks" in msg:
            return ErrorType.PROXY_ERROR
        elif "url" in msg or "invalid" in msg:
            return ErrorType.INVALID_URL
        else:
            return ErrorType.UNKNOWN_ERROR
