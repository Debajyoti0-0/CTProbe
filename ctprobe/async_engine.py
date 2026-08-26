"""Asynchronous aiohttp live-testing engine.

A single pooled :class:`aiohttp.ClientSession` drives bounded-concurrency HTTP
testing of many domains. This engine handles the ``auto``/``1.1`` path over
direct or HTTP/HTTPS-proxy routes only; explicit HTTP/2 or HTTP/3 and SOCKS/Tor
routes are dispatched to the synchronous threaded engine by
:mod:`ctprobe.live_test` (aiohttp negotiates HTTP/1.1 only and needs
``aiohttp_socks`` for SOCKS, which we deliberately do not require).

Design constraints (see the implementation spec):
- one reusable session + bounded connector (never a session per domain),
- bounded worker/queue scheduling (never one task per domain for large lists),
- no response-body download (status/headers/version only),
- report the *actually negotiated* protocol, never the requested one,
- fail-closed cleanup: session/connector always closed, partial results kept.
"""

import asyncio
import random
import ssl as ssl_module
import time
from typing import FrozenSet, List, Optional

from .models import LiveTestResult, ErrorType
from .logging_utils import Logger
from .http_client import resolve_headers
from .status_policy import DEFAULT_MATCH_CODES, classify_response
from .presentation import ProgressDisplay


# aiohttp is an optional-at-runtime import: the dispatcher only routes here when
# it is genuinely importable, but keep this module import-safe regardless.
try:
    import aiohttp
except ImportError:  # pragma: no cover - exercised via dispatcher fallback
    aiohttp = None


def _map_error(exc: Exception) -> ErrorType:
    """Map an aiohttp/asyncio transport exception to a structured ErrorType."""
    if aiohttp is None:  # pragma: no cover - defensive
        return ErrorType.UNKNOWN_ERROR

    if isinstance(exc, asyncio.TimeoutError):
        return ErrorType.CONNECTION_TIMEOUT
    if isinstance(exc, aiohttp.ClientConnectorCertificateError):
        return ErrorType.TLS_ERROR
    if isinstance(exc, aiohttp.ClientSSLError):
        return ErrorType.TLS_ERROR
    if isinstance(exc, aiohttp.ClientProxyConnectionError):
        return ErrorType.PROXY_ERROR
    if isinstance(exc, aiohttp.InvalidURL):
        return ErrorType.INVALID_URL
    if isinstance(exc, aiohttp.ClientConnectorError):
        # ClientConnectorError wraps the underlying OSError; a getaddrinfo
        # failure means DNS could not be resolved.
        message = str(exc).lower()
        if any(token in message for token in (
            "getaddrinfo", "name or service not known", "nodename nor servname",
            "name resolution", "temporary failure in name",
        )):
            return ErrorType.DNS_ERROR
        return ErrorType.CONNECTION_ERROR
    if isinstance(exc, aiohttp.ClientError):
        return ErrorType.CONNECTION_ERROR
    return ErrorType.UNKNOWN_ERROR


def _version_label(response) -> str:
    """Human label for the actually negotiated HTTP version."""
    version = getattr(response, "version", None)
    if version is None:
        return "HTTP/1.1"
    return f"HTTP/{version.major}.{version.minor}"


class AsyncLiveTester:
    """aiohttp-backed bounded-concurrency live tester."""

    MAX_REDIRECTS = 10

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0",
        headers: Optional[dict] = None,
        proxy: Optional[str] = None,
        bypass_tls: bool = False,
        match_codes: FrozenSet[int] = DEFAULT_MATCH_CODES,
        filter_codes: FrozenSet[int] = frozenset(),
        stealth: bool = False,
        stealth_min_delay: float = 1.0,
        stealth_max_delay: float = 3.0,
        logger: Optional[Logger] = None,
    ):
        if aiohttp is None:  # pragma: no cover - dispatcher guards this
            raise RuntimeError("aiohttp is not available")
        self.timeout = timeout
        self.user_agent = user_agent
        self.headers = headers or {}
        self.proxy = proxy
        self.bypass_tls = bypass_tls
        self.match_codes = match_codes
        self.filter_codes = filter_codes
        self.stealth = stealth
        self.stealth_min_delay = stealth_min_delay
        self.stealth_max_delay = stealth_max_delay
        self.logger = logger or Logger()

    def _request_headers(self) -> dict:
        # Shared resolver: explicit --header "User-Agent" wins (case-insensitively),
        # otherwise --user-agent; never a duplicate UA header. Identical precedence
        # to the threaded engine so both routes send the same User-Agent.
        return resolve_headers(self.headers, self.user_agent)

    def _ssl_option(self):
        """Per-session TLS setting: ``False`` disables verification (never global)."""
        if self.bypass_tls:
            return False
        return ssl_module.create_default_context()

    async def _test_one(self, session, domain: str) -> LiveTestResult:
        """Test a single domain, trying HTTPS then HTTP (scheme fallback)."""
        if self.stealth:
            await asyncio.sleep(
                random.uniform(self.stealth_min_delay, self.stealth_max_delay)
            )

        last_error_type: Optional[ErrorType] = None
        last_error_msg: Optional[str] = None
        last_scheme: Optional[str] = None

        for scheme in ("https://", "http://"):
            url = scheme + domain
            last_scheme = scheme
            start = time.monotonic()
            try:
                async with session.get(
                    url,
                    allow_redirects=True,
                    max_redirects=self.MAX_REDIRECTS,
                    proxy=self.proxy,
                    ssl=self._ssl_option(),
                ) as response:
                    # Status/headers/version only — never download the body.
                    elapsed_ms = (time.monotonic() - start) * 1000
                    status_code = response.status
                    headers = response.headers
                    classification = classify_response(
                        status_code, self.match_codes, self.filter_codes
                    )
                    return LiveTestResult(
                        domain=domain,
                        live=classification.live,
                        attempted_url=url,
                        network_reachable=classification.network_reachable,
                        http_response_received=classification.http_response_received,
                        status_code=status_code,
                        status_matched=classification.status_matched,
                        status_filtered=classification.status_filtered,
                        scheme=scheme.rstrip(":/"),
                        final_url=str(response.url),
                        http_version=_version_label(response),
                        response_time_ms=elapsed_ms,
                        redirect_count=len(response.history),
                        server=headers.get("Server"),
                        content_type=headers.get("Content-Type"),
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - mapped to structured ErrorType
                last_error_type = _map_error(exc)
                last_error_msg = str(exc) or exc.__class__.__name__
                continue

        # Neither scheme produced an HTTP response.
        return LiveTestResult(
            domain=domain,
            live=False,
            attempted_url=(last_scheme + domain) if last_scheme else None,
            network_reachable=False,
            http_response_received=False,
            error=last_error_msg or "No reachable scheme (HTTPS and HTTP both failed)",
            error_type=last_error_type or ErrorType.CONNECTION_ERROR,
            scheme=last_scheme.rstrip(":/") if last_scheme else None,
        )

    async def run(
        self,
        domains: List[str],
        effective_workers: int,
        progress: Optional[ProgressDisplay] = None,
    ) -> List[LiveTestResult]:
        """Drain ``domains`` through a bounded pool of workers and return results.

        Resources are always released; on cancellation the partially collected
        results are returned rather than lost.
        """
        results: List[LiveTestResult] = []
        if not domains:
            return results

        # The dispatcher only routes here when aiohttp is importable and __init__
        # already rejects a None module; re-assert it so the module-level Optional
        # import narrows to non-None for the type checker (and stays -O safe).
        if aiohttp is None:  # pragma: no cover - dispatcher guards this
            raise RuntimeError("aiohttp is not available")

        workers = max(1, effective_workers)
        queue: asyncio.Queue = asyncio.Queue()
        for domain in domains:
            queue.put_nowait(domain)

        connector = aiohttp.TCPConnector(limit=workers, ssl=self._ssl_option())
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async def worker(session) -> None:
            while True:
                try:
                    domain = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    result = await self._test_one(session, domain)
                except asyncio.CancelledError:
                    # Re-queue is unnecessary; stop consuming and unwind.
                    queue.task_done()
                    raise
                results.append(result)
                if result.live:
                    self.logger.verbose_msg(
                        f"LIVE {result.domain} [{result.http_version}] "
                        f"{result.status_code} {result.final_url}"
                    )
                else:
                    self.logger.debug_msg(f"DEAD {result.domain}: {result.error}")
                if progress is not None:
                    progress.update(
                        live=result.live,
                        matched=result.status_matched,
                        filtered=result.status_filtered,
                        failed=not result.http_response_received,
                    )
                queue.task_done()

        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._request_headers(),
            trust_env=False,
        )
        tasks = [asyncio.ensure_future(worker(session)) for _ in range(workers)]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        finally:
            await session.close()
            if progress is not None:
                progress.stop()

        results.sort(key=lambda r: r.domain)
        return results
