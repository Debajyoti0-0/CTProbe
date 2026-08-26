"""Live subdomain testing engine."""

import asyncio
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.util import find_spec
from typing import FrozenSet, List, Optional
from urllib.parse import urlparse

from .models import LiveTestResult, ErrorType
from .http_client import HTTPClient, HTTPClientError
from .logging_utils import Logger
from .status_policy import DEFAULT_MATCH_CODES, classify_response
from .presentation import ProgressDisplay


def _aiohttp_available() -> bool:
    """Whether aiohttp is importable in this runtime."""
    try:
        return find_spec("aiohttp") is not None
    except (ImportError, ValueError):
        return False


def _proxy_url(proxies: Optional[dict]) -> Optional[str]:
    """Single proxy URL from a ``{"http":..,"https":..}`` mapping (they match)."""
    if not proxies:
        return None
    return proxies.get("https") or proxies.get("http")


def _is_socks_route(proxies: Optional[dict]) -> bool:
    """True when the effective proxy uses a SOCKS scheme (aiohttp can't route it)."""
    url = _proxy_url(proxies)
    if not url:
        return False
    return urlparse(url).scheme.lower().startswith("socks")


class LiveTester:
    """Tests discovered subdomains for reachability."""

    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger()
    
    def test_domain(
        self,
        domain: str,
        http_version: str = "auto",
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0",
        headers: Optional[dict] = None,
        proxies: Optional[dict] = None,
        bypass_tls: bool = False,
        force: bool = False,
        match_codes: FrozenSet[int] = DEFAULT_MATCH_CODES,
        filter_codes: FrozenSet[int] = frozenset(),
    ) -> LiveTestResult:
        """
        Test if a single domain is live.

        Attempts HTTPS first, then HTTP. ``force`` disables HTTP *version*
        fallback only (handled inside :class:`HTTPClient`); the https->http
        *scheme* fallback still happens regardless of ``force`` (spec §46).
        """
        headers = headers or {}

        client = HTTPClient(
            timeout=timeout,
            user_agent=user_agent,
            headers=headers,
            proxies=proxies,
            bypass_tls=bypass_tls,
            logger=self.logger,
        )

        last_error: Optional[HTTPClientError] = None
        last_scheme: Optional[str] = None

        # Try HTTPS first, then HTTP.
        for scheme in ["https://", "http://"]:
            url = scheme + domain
            last_scheme = scheme

            try:
                response = client.request(
                    url,
                    http_version=http_version,
                    force=force,
                )
            except HTTPClientError as exc:
                last_error = exc
                continue

            classification = classify_response(
                response["status_code"], match_codes, filter_codes
            )
            return LiveTestResult(
                domain=domain,
                live=classification.live,
                attempted_url=url,
                network_reachable=classification.network_reachable,
                http_response_received=classification.http_response_received,
                status_code=response["status_code"],
                status_matched=classification.status_matched,
                status_filtered=classification.status_filtered,
                scheme=scheme.rstrip(":/"),
                final_url=response["final_url"],
                http_version=response["http_version"],
                response_time_ms=response.get("response_time_ms"),
                redirect_count=response.get("redirect_count", 0),
                server=response.get("server"),
                content_type=response.get("content_type"),
            )

        # Neither HTTPS nor HTTP worked.
        error_type = last_error.error_type if last_error else ErrorType.CONNECTION_ERROR
        error_msg = (
            str(last_error) if last_error
            else "No reachable scheme (HTTPS and HTTP both failed)"
        )
        return LiveTestResult(
            domain=domain,
            live=False,
            attempted_url=(last_scheme + domain) if last_scheme else None,
            network_reachable=False,
            http_response_received=False,
            error=error_msg,
            error_type=error_type,
            scheme=last_scheme.rstrip(":/") if last_scheme else None,
        )
    
    def test_domains(
        self,
        domains: List[str],
        workers: int = 10,
        stealth: bool = False,
        stealth_min_delay: float = 1.0,
        stealth_max_delay: float = 3.0,
        http_version: str = "auto",
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0",
        headers: Optional[dict] = None,
        proxies: Optional[dict] = None,
        bypass_tls: bool = False,
        force: bool = False,
        match_codes: FrozenSet[int] = DEFAULT_MATCH_CODES,
        filter_codes: FrozenSet[int] = frozenset(),
        no_color: bool = False,
    ) -> List[LiveTestResult]:
        """
        Test multiple domains for reachability with concurrency.
        
        Returns list of LiveTestResult objects.
        """
        if not domains:
            return []
        
        total = len(domains)
        headers = headers or {}
        results = []
        
        # Adjust worker count for stealth mode
        effective_workers = workers
        if stealth:
            effective_workers = min(workers, 3)
            self.logger.info(f"[*] Stealth mode: {effective_workers} workers")
            self.logger.info(
                f"[*] Delay: {stealth_min_delay:.2f}-{stealth_max_delay:.2f}s"
            )
        
        self.logger.info(f"[*] Testing {total} subdomains...")
        progress = ProgressDisplay(
            total,
            show_progress=not self.logger.quiet,
            use_rich=not no_color,
        )

        # Engine dispatch: aiohttp handles the common auto/1.1 path over direct or
        # HTTP/HTTPS-proxy routes. Explicit HTTP/2/3 and SOCKS/Tor routes stay on
        # the threaded engine (aiohttp is HTTP/1.1-only and needs aiohttp_socks
        # for SOCKS, which we deliberately do not require).
        socks_route = _is_socks_route(proxies)
        if http_version in ("auto", "1.1") and not socks_route and _aiohttp_available():
            self.logger.verbose_msg("[*] Async HTTP engine: aiohttp")
            self.logger.info(f"[*] Effective concurrency: {effective_workers}")
            return self._run_async(
                domains=domains,
                effective_workers=effective_workers,
                progress=progress,
                timeout=timeout,
                user_agent=user_agent,
                headers=headers,
                proxies=proxies,
                bypass_tls=bypass_tls,
                match_codes=match_codes,
                filter_codes=filter_codes,
                stealth=stealth,
                stealth_min_delay=stealth_min_delay,
                stealth_max_delay=stealth_max_delay,
            )

        if http_version in ("2", "3"):
            reason = f"HTTP/{http_version} not supported by aiohttp"
        elif socks_route:
            reason = "SOCKS/Tor route"
        else:
            reason = "aiohttp unavailable"
        self.logger.info(f"[*] HTTP engine: threaded ({reason})")

        def test_with_stealth(domain: str) -> LiveTestResult:
            """Test domain with optional stealth delay."""
            if stealth:
                delay = random.uniform(stealth_min_delay, stealth_max_delay)
                time.sleep(delay)
            
            return self.test_domain(
                domain,
                http_version=http_version,
                timeout=timeout,
                user_agent=user_agent,
                headers=headers,
                proxies=proxies,
                bypass_tls=bypass_tls,
                force=force,
                match_codes=match_codes,
                filter_codes=filter_codes,
            )
        
        completed = 0
        
        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = {
                executor.submit(test_with_stealth, domain): domain
                for domain in domains
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.live:
                        self.logger.verbose_msg(
                            f"LIVE {result.domain} "
                            f"[{result.http_version}] "
                            f"{result.status_code} "
                            f"{result.final_url}"
                        )
                    else:
                        self.logger.debug_msg(
                            f"DEAD {result.domain}: {result.error}"
                        )
                
                except Exception as exc:
                    # Individual domain test failed
                    result = LiveTestResult(
                        domain=futures[future],
                        live=False,
                        error=str(exc),
                        error_type=ErrorType.UNKNOWN_ERROR,
                    )
                    results.append(result)

                progress.update(
                    live=result.live,
                    matched=result.status_matched,
                    filtered=result.status_filtered,
                    failed=not result.http_response_received,
                )
                
                completed += 1
                
            progress.stop()
        
        results.sort(key=lambda x: x.domain)

        return results

    def _run_async(
        self,
        domains: List[str],
        effective_workers: int,
        progress: ProgressDisplay,
        timeout: float,
        user_agent: str,
        headers: dict,
        proxies: Optional[dict],
        bypass_tls: bool,
        match_codes: FrozenSet[int],
        filter_codes: FrozenSet[int],
        stealth: bool,
        stealth_min_delay: float,
        stealth_max_delay: float,
    ) -> List[LiveTestResult]:
        """Run the aiohttp engine synchronously via ``asyncio.run``."""
        from .async_engine import AsyncLiveTester

        tester = AsyncLiveTester(
            timeout=timeout,
            user_agent=user_agent,
            headers=headers,
            proxy=_proxy_url(proxies),
            bypass_tls=bypass_tls,
            match_codes=match_codes,
            filter_codes=filter_codes,
            stealth=stealth,
            stealth_min_delay=stealth_min_delay,
            stealth_max_delay=stealth_max_delay,
            logger=self.logger,
        )
        return asyncio.run(
            tester.run(domains, effective_workers, progress)
        )
