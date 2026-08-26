"""Unified, fail-closed network routing configuration.

Single source of truth for the effective proxy used by BOTH Certificate
Transparency discovery and HTTP availability testing. When ``--tor``/``--proxy``
is requested, routing is *fail-closed*: no scanner traffic is issued unless the
proxy has been verified. Tor is only reported as verified after an actual
proxied request confirms it (``IsTor: true``); a generic SOCKS proxy is never
silently treated as Tor.
"""

import socket
import time
from dataclasses import dataclass
from importlib.util import find_spec
from typing import Dict, Optional, Union
from urllib.parse import urlparse

import requests

from .logging_utils import Logger, redact_credentials


DEFAULT_TOR_ENDPOINT = "socks5h://127.0.0.1:9050"
DEFAULT_TOR_PORT = 9050
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
NEUTRAL_CHECK_URL = "https://icanhazip.com"

SOCKS_SCHEMES = frozenset({"socks4", "socks4a", "socks5", "socks5h"})
SUPPORTED_SCHEMES = SOCKS_SCHEMES | {"http", "https"}

# Timeouts (seconds) per spec: SOCKS reachability 5s, connectivity test 10s.
SOCKS_CONNECT_TIMEOUT = 5.0
CONNECTIVITY_TIMEOUT = 10.0


class NetworkError(Exception):
    """Raised for invalid or unsupported proxy configuration."""


@dataclass(frozen=True)
class NetworkConfig:
    """Effective network routing shared by every client in a scan."""
    proxies: Optional[Dict[str, str]]
    is_tor: bool
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    display_url: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return self.proxies is not None


def _socks_available() -> bool:
    """Whether PySocks (the ``socks`` module) is importable."""
    return find_spec("socks") is not None


def validate_socks_capability(scheme: str) -> None:
    """Ensure the transport can actually execute the requested SOCKS scheme."""
    if scheme in SOCKS_SCHEMES and not _socks_available():
        raise NetworkError(
            f"{scheme} is unavailable: PySocks is not installed. "
            "Install with: pip install 'requests[socks]'"
        )


def build_network_config(
    tor: Optional[Union[bool, str]] = None,
    proxy: Optional[str] = None,
) -> NetworkConfig:
    """Build the effective :class:`NetworkConfig` from CLI ``tor``/``proxy``.

    ``tor`` may be ``None`` (disabled), ``True`` (bare ``--tor``, use the default
    endpoint), or an explicit endpoint string.
    """
    if tor is not None and proxy:
        raise NetworkError("--tor and --proxy cannot be combined.")

    if tor is not None:
        raw = DEFAULT_TOR_ENDPOINT if tor is True else str(tor).strip()
        is_tor = True
        default_scheme = "socks5h"
    elif proxy:
        raw = str(proxy).strip()
        is_tor = False
        default_scheme = "http"
    else:
        return NetworkConfig(proxies=None, is_tor=False)

    if not raw:
        raise NetworkError("Empty proxy endpoint.")

    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"

    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise NetworkError(
            f"Unsupported proxy scheme {scheme!r}. "
            f"Supported: {', '.join(sorted(SUPPORTED_SCHEMES))}."
        )

    validate_socks_capability(scheme)

    host = parsed.hostname
    if not host:
        raise NetworkError(f"Proxy endpoint is missing a host: {redact_credentials(raw)}")

    port = parsed.port
    if port is None:
        if is_tor:
            port = DEFAULT_TOR_PORT
        else:
            raise NetworkError(
                f"Proxy endpoint is missing a port: {redact_credentials(raw)}"
            )

    proxies = {"http": raw, "https": raw}
    return NetworkConfig(
        proxies=proxies,
        is_tor=is_tor,
        scheme=scheme,
        host=host,
        port=port,
        display_url=redact_credentials(raw),
    )


def _socks_reachable(host: str, port: int, timeout: float = SOCKS_CONNECT_TIMEOUT) -> bool:
    """Return True if a TCP connection to the proxy endpoint can be opened."""
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=max(0.1, deadline - time.monotonic())):
            return True
    except OSError:
        return False


def verify(config: NetworkConfig, timeout: float = CONNECTIVITY_TIMEOUT,
           logger: Optional[Logger] = None) -> bool:
    """Verify routing before any scan traffic. Returns True only when READY.

    State: CONFIGURED -> CHECKING (socket) -> VERIFYING (proxied request) ->
    READY | FAILED. For ``--tor`` the proxied request must confirm ``IsTor: true``;
    a reachable-but-non-Tor SOCKS proxy is a failure under ``--tor``.
    """
    logger = logger or Logger()

    if not config.enabled:
        return True

    # An enabled config always carries a resolved host/port (build_network_config
    # rejects otherwise); assert to narrow the Optionals for reachability.
    if config.host is None or config.port is None:
        logger.error("Proxy endpoint is incompletely configured.")
        return False

    # CHECKING: is the SOCKS/proxy endpoint reachable at all?
    if not _socks_reachable(config.host, config.port):
        logger.error(f"Proxy endpoint is not reachable: {config.display_url}")
        return False
    logger.info("SOCKS proxy reachable.")

    # VERIFYING: issue a real proxied request.
    connect_timeout = min(CONNECTIVITY_TIMEOUT, max(timeout, 5.0))
    check_url = TOR_CHECK_URL if config.is_tor else NEUTRAL_CHECK_URL
    logger.info(f"Verifying {'Tor' if config.is_tor else 'proxy'} connectivity...")

    try:
        response = requests.get(
            check_url,
            proxies=config.proxies,
            timeout=connect_timeout,
            headers={"User-Agent": "Mozilla/5.0 (Scanner)"},
        )
    except requests.RequestException as exc:
        logger.error(f"Proxy connectivity test failed: {exc}")
        return False

    if config.is_tor:
        try:
            data = response.json()
        except ValueError:
            data = {}
        if not data.get("IsTor"):
            logger.error(
                "Endpoint is reachable but Tor could not be confirmed (IsTor=false). "
                "Refusing to route a non-Tor proxy as Tor."
            )
            return False
        logger.info("Tor connectivity verified.")
        return True

    if response.status_code >= 500:
        logger.error(
            f"Proxy connectivity test returned HTTP {response.status_code}."
        )
        return False
    logger.info("Proxy connectivity verified.")
    return True
