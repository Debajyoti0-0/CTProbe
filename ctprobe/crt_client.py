"""Certificate Transparency data client."""

import requests
from typing import Optional, Set, Tuple

from .domain import extract_domain_names_from_text
from .models import DiscoveryResult, ErrorType
from .logging_utils import Logger


CRT_ENDPOINT = "https://crt.name/v1/search"


class CRTError(Exception):
    """CRT client error."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class CRTClient:
    """Client for querying Certificate Transparency data from crt.name."""
    
    def __init__(
        self,
        timeout: float = 10.0,
        logger: Optional[Logger] = None,
        proxies: Optional[dict] = None,
    ):
        self.timeout = timeout
        self.logger = logger or Logger()
        # Routing shared with the HTTP scanner so discovery never bypasses Tor.
        self.proxies = proxies
    
    def fetch_domains(self, domain: str) -> Tuple[Set[str], str]:
        """
        Fetch unique certificate DNS names from CRT.name for an apex domain.

        Returns:
            Tuple of (names_set, http_version)

        Raises:
            CRTError: On request failure
        """
        result = self.discover_domains(domain)
        if not result.success:
            raise CRTError(result.error or "CRT discovery failed", result.status_code)
        return set(result.domains), "HTTP/1.1"

    def discover_domains(self, domain: str) -> DiscoveryResult:
        """Query CRT and return a structured success or failure outcome."""
        params = {"apex": domain}
        self.logger.debug_msg(f"CRT target: {domain}")
        self.logger.debug_msg(f"CRT endpoint: {CRT_ENDPOINT}")
        
        try:
            response = requests.get(
                CRT_ENDPOINT,
                params=params,
                timeout=self.timeout,
                proxies=self.proxies,
                headers={
                    "User-Agent": "Mozilla/5.0 (Scanner)"
                }
            )
            
            self.logger.debug_msg(f"CRT response status: {response.status_code}")
            self.logger.debug_msg(
                f"CRT Content-Type: {response.headers.get('content-type', '')}"
            )
            self.logger.debug_msg(
                f"CRT response: {response.text[:240].replace(chr(10), ' ')}"
            )
            
            if response.status_code == 429:
                return DiscoveryResult(False, status_code=429, error="HTTP 429 - Rate limited")
            
            if response.status_code == 413:
                return DiscoveryResult(False, status_code=413, error="HTTP 413 - Payload too large")
            
            if response.status_code >= 400:
                return DiscoveryResult(False, status_code=response.status_code, error=f"HTTP {response.status_code}")
            
            if not response.text:
                return DiscoveryResult(False, status_code=response.status_code, error="Empty response")
            
            domains = extract_domain_names_from_text(response.text)
            
            return DiscoveryResult(True, domains=sorted(domains), status_code=response.status_code, raw_count=len(domains))
            
        except requests.exceptions.Timeout:
            return DiscoveryResult(False, error="Timeout")
        except requests.exceptions.ConnectionError as exc:
            return DiscoveryResult(False, error=f"Connection error: {exc}")
        except requests.exceptions.RequestException as exc:
            return DiscoveryResult(False, error=f"Request failed: {exc}")
        except Exception as exc:
            return DiscoveryResult(False, error=f"Unexpected error: {exc}")
    
    @staticmethod
    def classify_error(error_msg: str) -> ErrorType:
        """Classify an error message into an ErrorType."""
        msg_lower = error_msg.lower()
        
        if "timeout" in msg_lower:
            return ErrorType.CONNECTION_TIMEOUT
        elif "dns" in msg_lower or "name resolution" in msg_lower:
            return ErrorType.DNS_ERROR
        elif "connection" in msg_lower or "refused" in msg_lower:
            return ErrorType.CONNECTION_ERROR
        elif "tls" in msg_lower or "ssl" in msg_lower or "certificate" in msg_lower:
            return ErrorType.TLS_ERROR
        elif "429" in msg_lower:
            return ErrorType.HTTP_429
        elif "5" in msg_lower and msg_lower.count("0") >= 1:
            return ErrorType.HTTP_5XX
        elif "proxy" in msg_lower:
            return ErrorType.PROXY_ERROR
        elif "url" in msg_lower or "invalid" in msg_lower:
            return ErrorType.INVALID_URL
        else:
            return ErrorType.UNKNOWN_ERROR
