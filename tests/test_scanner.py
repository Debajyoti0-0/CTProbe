"""Comprehensive test suite for ctprobe."""

import pytest
import os
import sys
import json
import types
import tempfile
from unittest.mock import patch, MagicMock

from ctprobe.domain import (
    normalize_domain,
    is_valid_domain,
    extract_domain_names_from_text,
    deduplicate_domains,
    normalize_wildcard,
    get_registrable_domain,
    is_subdomain_of,
)
from ctprobe.models import LiveTestResult, ErrorType, ThreatLevel
from ctprobe.threat import analyze_threat
from ctprobe.logging_utils import Logger, redact_credentials
from ctprobe.output import (
    safe_filename,
    save_txt,
    save_json,
    make_output_path,
)
from ctprobe.status_policy import (
    DEFAULT_MATCH_CODES,
    StatusCodeError,
    classify_response,
    format_status_codes,
    parse_status_codes,
)


class TestDomainNormalization:
    """Test domain normalization."""
    
    def test_lowercase(self):
        """Test lowercase conversion."""
        assert normalize_domain("Example.COM") == "example.com"
        assert normalize_domain("GOOGLE.COM") == "google.com"
    
    def test_trailing_dot_removal(self):
        """Test trailing dot removal."""
        assert normalize_domain("example.com.") == "example.com"
        assert normalize_domain("test.org...") == "test.org"
    
    def test_whitespace_stripping(self):
        """Test whitespace removal."""
        assert normalize_domain("  example.com  ") == "example.com"
        assert normalize_domain("\nexample.com\t") == "example.com"
    
    def test_scheme_removal(self):
        """Test scheme removal from URLs."""
        assert normalize_domain("https://example.com") == "example.com"
        assert normalize_domain("http://example.com") == "example.com"
        assert normalize_domain("ftp://example.com") == "example.com"
    
    def test_path_and_port_removal(self):
        """Test path and port removal."""
        assert normalize_domain("example.com:8080") == "example.com"
        assert normalize_domain("example.com/path") == "example.com"
    
    def test_empty_input(self):
        """Test empty or invalid input."""
        assert normalize_domain("") == ""
        assert normalize_domain("   ") == ""
        assert normalize_domain("invalid") == ""
    
    def test_valid_domain(self):
        """Test valid domain."""
        assert normalize_domain("example.com") == "example.com"
        assert normalize_domain("sub.example.com") == "sub.example.com"


class TestDomainValidation:
    """Test domain validation."""
    
    def test_valid_domains(self):
        """Test valid domain names."""
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.com")
        assert is_valid_domain("a.co")
        assert is_valid_domain("localhost")
    
    def test_invalid_domains(self):
        """Test invalid domain names."""
        assert not is_valid_domain("")
        assert not is_valid_domain("invalid")
        assert not is_valid_domain("-example.com")
        assert not is_valid_domain("example-.com")
        assert not is_valid_domain("ex ample.com")

    @pytest.mark.parametrize("value, expected", [
        ("https://www.example.com/", "www.example.com"),
        ("http://www.example.com/path?a=1#x", "www.example.com"),
        ("HTTPS://API.EXAMPLE.COM/PATH", "api.example.com"),
    ])
    def test_url_target_normalization(self, value, expected):
        assert normalize_domain(value) == expected

    @pytest.mark.parametrize("value, expected", [
        ("www.example.com", "example.com"),
        ("api.example.co.uk", "example.co.uk"),
        ("api.example.com.au", "example.com.au"),
        ("example.co.in", "example.co.in"),
    ])
    def test_registrable_domain_preserves_public_suffix_semantics(self, value, expected):
        assert get_registrable_domain(value) == expected


class TestDomainExtraction:
    """Test certificate DNS name extraction from text."""
    
    def test_extract_simple_domains(self):
        """Test extracting simple names."""
        text = "Visit example.com or test.org today"
        domains = extract_domain_names_from_text(text)
        assert "example.com" in domains
        assert "test.org" in domains

    def test_extract_subdomains(self):
        """Test extracting subdomains."""
        text = "api.example.com and web.test.org"
        domains = extract_domain_names_from_text(text)
        assert "api.example.com" in domains
        assert "web.test.org" in domains

    def test_extract_case_insensitive(self):
        """Test case-insensitive extraction."""
        text = "Example.COM and TEST.ORG"
        domains = extract_domain_names_from_text(text)
        # Should be lowercase
        assert "example.com" in domains
        assert "test.org" in domains

    def test_empty_text(self):
        """Test empty text."""
        assert extract_domain_names_from_text("") == set()
        assert extract_domain_names_from_text(None) == set()


class TestSubdomainMembership:
    """Label-aware subdomain membership (no bare suffix matching)."""

    def test_apex_itself_is_member(self):
        assert is_subdomain_of("example.com", "example.com")

    def test_direct_and_deep_subdomains(self):
        assert is_subdomain_of("www.example.com", "example.com")
        assert is_subdomain_of("foo.bar.example.com", "example.com")

    def test_suffix_lookalike_is_rejected(self):
        # evil-example.com must NOT match example.com (label boundary).
        assert not is_subdomain_of("evil-example.com", "example.com")
        assert not is_subdomain_of("example.com.evil.net", "example.com")

    def test_unrelated_domains_rejected(self):
        assert not is_subdomain_of("example.net", "example.com")
        assert not is_subdomain_of("example.org", "example.com")

    def test_case_and_trailing_dot_normalized(self):
        assert is_subdomain_of("WWW.Example.COM.", "example.com")


class TestDomainDeduplication:
    """Test domain deduplication."""
    
    def test_deduplicate_exact(self):
        """Test deduplicating exact matches."""
        domains = ["example.com", "example.com", "test.org"]
        result = deduplicate_domains(domains)
        assert result == ["example.com", "test.org"]
    
    def test_deduplicate_case_insensitive(self):
        """Test case-insensitive deduplication."""
        domains = ["Example.COM", "example.com", "EXAMPLE.COM"]
        result = deduplicate_domains(domains)
        assert result == ["example.com"]
    
    def test_sorted_output(self):
        """Test output is sorted."""
        domains = ["zebra.com", "apple.com", "middle.com"]
        result = deduplicate_domains(domains)
        assert result == ["apple.com", "middle.com", "zebra.com"]


class TestWildcardHandling:
    """Test wildcard certificate handling."""
    
    def test_wildcard_removal(self):
        """Test removing wildcard prefix."""
        assert normalize_wildcard("*.example.com") == "example.com"
        assert normalize_wildcard("example.com") == "example.com"


class TestThreatAnalysis:
    """Test threat analysis heuristics."""
    
    def test_suspicious_tld(self):
        """Test suspicious TLD detection."""
        result = analyze_threat("example.zip")
        assert result["threat_score"] >= 2
        assert "suspicious_tld:zip" in result["threat_indicators"]
    
    def test_suspicious_keywords(self):
        """Test suspicious keyword detection."""
        result = analyze_threat("login-verify-example.com")
        assert result["threat_score"] > 0
        assert any("keyword:" in ind for ind in result["threat_indicators"])
    
    def test_very_long_domain(self):
        """Test very long domain detection."""
        long_domain = "a" * 60 + ".com"
        result = analyze_threat(long_domain)
        assert "very_long_domain" in result["threat_indicators"]
    
    def test_excessive_hyphens(self):
        """Test excessive hyphens detection."""
        result = analyze_threat("a-b-c-d-example.com")
        assert "many_hyphens" in result["threat_indicators"]
    
    def test_threat_level_classification(self):
        """Test threat level classification."""
        # Low threat
        result = analyze_threat("example.com")
        assert result["threat_level"] == ThreatLevel.NONE
        
        # High threat
        result = analyze_threat("a-b-c-d-login-verify-secure.zip")
        assert result["threat_level"] in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]

    def test_discovery_threat_json_serializes_and_counts(self):
        """Discovery + threat + JSON must serialize (enum -> value) and count.

        Regression: analyze_threat returns a ThreatLevel *enum*; the discovery
        path fed those enums straight into json.dump (TypeError) and compared
        them to the strings "high"/"medium"/"low" (always False). Both are
        rooted in the same missing enum->value normalization.
        """
        from ctprobe.output import save_discovery_output

        # Mirror the dict construction in main._save_discovery_results.
        domains = ["a-b-c-d-login-verify-secure.zip", "example.com"]
        threat_results = []
        for d in domains:
            data = analyze_threat(d)
            data["threat_level"] = data["threat_level"].value
            row = {"domain": d}
            row.update(data)
            threat_results.append(row)

        # Summary comparisons against plain strings must now work.
        assert any(r["threat_level"] in ("high", "medium", "low")
                   for r in threat_results)

        with tempfile.TemporaryDirectory() as tmp:
            path = save_discovery_output(
                domains=domains,
                output_dir=tmp,
                domain="example.com",
                output_format="json",
                threat_results=threat_results,
            )
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
        # Round-trips as plain JSON strings, never enum reprs.
        assert all(isinstance(r["threat_level"], str) for r in loaded)


class TestOutputFormatting:
    """Test output formatting utilities."""
    
    def test_safe_filename(self):
        """Test filename sanitization."""
        assert safe_filename("example.com") == "example.com"
        assert safe_filename("test@domain.com") == "test_domain.com"
        assert safe_filename("my/path\\domain.com") == "my_path_domain.com"
    
    def test_save_txt(self):
        """Test TXT file output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.txt")
            domains = ["example.com", "test.org"]
            
            save_txt(domains, filepath)
            
            with open(filepath, "r") as f:
                content = f.read()
            
            assert "example.com\n" in content
            assert "test.org\n" in content
    
    def test_save_json(self):
        """Test JSON file output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.json")
            data = {"domain": "example.com", "status": "live"}
            
            save_json(data, filepath)
            
            with open(filepath, "r") as f:
                loaded = json.load(f)
            
            assert loaded["domain"] == "example.com"
    
    def test_make_output_path_live(self):
        """Test output path generation for live testing."""
        path = make_output_path(
            output_dir="Outputs",
            filename=None,
            domain="example.com",
            suffix="LIVE",
            output_format="txt",
        )
        
        assert "example.com" in path
        assert "LIVE-output" in path
        assert path.endswith(".txt")
    
    def test_make_output_path_all(self):
        """Test output path generation for all results."""
        path = make_output_path(
            output_dir="Outputs",
            filename=None,
            domain="example.com",
            suffix="ALL",
            output_format="json",
        )
        
        assert "example.com" in path
        assert "ALL-output" in path
        assert path.endswith(".json")


class TestLiveTestResult:
    """Test LiveTestResult model."""
    
    def test_result_creation(self):
        """Test creating a result."""
        result = LiveTestResult(
            domain="example.com",
            live=True,
            status_code=200,
            scheme="https",
            final_url="https://example.com/",
            http_version="HTTP/2",
        )
        
        assert result.domain == "example.com"
        assert result.live
        assert result.status_code == 200
    
    def test_result_to_dict(self):
        """Test converting result to dict."""
        result = LiveTestResult(
            domain="example.com",
            live=True,
            status_code=200,
            threat_level=ThreatLevel.LOW,
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["domain"] == "example.com"
        assert result_dict["live"] is True
        assert result_dict["threat_level"] == "low"


class TestErrorClassification:
    """Test error type classification."""
    
    def test_classify_timeout_error(self):
        """Test timeout error classification."""
        from ctprobe.http_client import HTTPClient
        
        error_type = HTTPClient.classify_error("Request timeout")
        assert error_type == ErrorType.CONNECTION_TIMEOUT
    
    def test_classify_dns_error(self):
        """Test DNS error classification."""
        from ctprobe.http_client import HTTPClient
        
        error_type = HTTPClient.classify_error("DNS resolution failed")
        assert error_type == ErrorType.DNS_ERROR
    
    def test_classify_tls_error(self):
        """Test TLS error classification."""
        from ctprobe.http_client import HTTPClient
        
        error_type = HTTPClient.classify_error("SSL certificate error")
        assert error_type == ErrorType.TLS_ERROR


class TestStatusPolicy:
    """Test HTTP status parsing and centralized classification."""

    def test_parse_codes_and_ranges(self):
        assert parse_status_codes("200, 250-252, 301") == frozenset(
            {200, 250, 251, 252, 301}
        )
        assert parse_status_codes("ALL") == frozenset(range(100, 600))

    @pytest.mark.parametrize("expression", [
        "abc", "99", "600", "200-", "-300", "300-200", "200--300",
        ",", "200,,301",
    ])
    def test_reject_invalid_codes(self, expression):
        with pytest.raises(StatusCodeError):
            parse_status_codes(expression)

    @pytest.mark.parametrize("status_code, matched", [
        (200, True), (201, True), (204, True), (301, True), (302, True),
        (307, True), (401, True), (403, True), (405, True), (500, True),
        (404, False), (429, False), (502, False), (503, False),
    ])
    def test_default_matching(self, status_code, matched):
        result = classify_response(
            status_code, DEFAULT_MATCH_CODES, frozenset()
        )
        assert result.status_matched is matched
        assert result.live is matched
        assert result.http_response_received
        assert result.network_reachable

    def test_filter_precedence(self):
        result = classify_response(
            500, frozenset(range(100, 600)), frozenset({404, 500})
        )
        assert result.status_filtered
        assert not result.status_matched
        assert not result.live

    def test_network_failure_has_no_http_response(self):
        result = classify_response(
            None, DEFAULT_MATCH_CODES, frozenset(), ErrorType.CONNECTION_TIMEOUT
        )
        assert not result.http_response_received
        assert not result.network_reachable
        assert not result.live
        assert result.error_type == ErrorType.CONNECTION_TIMEOUT

    def test_format_status_codes_as_ranges(self):
        assert format_status_codes(frozenset({200, 201, 202, 204, 301})) == (
            "200-202,204,301"
        )

    def test_format_empty_status_codes(self):
        assert format_status_codes(frozenset()) == "NONE"


class TestCliPolicies:
    """Test CLI policy parsing and explicit mode selection."""

    def test_match_filter_config(self):
        from ctprobe.cli import build_config, create_parser

        args = create_parser().parse_args([
            "example.com", "-mc", "all", "-fc", "404,500-599"
        ])
        config = build_config(args)
        assert config.live_mode is True
        assert 200 in config.match_codes
        assert 404 in config.filter_codes
        assert 500 in config.filter_codes

    def test_match_code_automatically_enables_testing(self):
        from ctprobe.cli import build_config, create_parser

        args = create_parser().parse_args(["example.com", "-mc", "200"])
        config = build_config(args)
        assert config.live_mode is True
        assert config.match_code_requested

    def test_filter_code_automatically_enables_testing(self):
        from ctprobe.cli import build_config, create_parser

        args = create_parser().parse_args(["example.com", "-fc", "404"])
        config = build_config(args)
        assert config.live_mode is True
        assert config.filter_code_requested

    def test_requested_expressions_are_preserved(self):
        from ctprobe.cli import build_config, create_parser

        args = create_parser().parse_args([
            "example.com", "-mc", "200-299,301", "-fc", "204, 404"
        ])
        config = build_config(args)
        assert config.match_code_expression == "200-299,301"
        assert config.filter_code_expression == "204, 404"

    def test_match_code_and_no_live_rejected(self):
        from ctprobe.cli import create_parser, validate_arguments

        parser = create_parser()
        args = parser.parse_args(["example.com", "-mc", "200", "--no-live"])
        with pytest.raises(SystemExit):
            validate_arguments(args, parser)

    def test_empty_effective_match_set_rejected(self):
        from ctprobe.cli import build_config, create_parser

        args = create_parser().parse_args([
            "example.com", "-mc", "200-299", "-fc", "200-299"
        ])
        with pytest.raises(ValueError, match="removes all"):
            build_config(args)

    def test_bare_tor_passthrough(self):
        """Bare --tor stays True (use the default Tor endpoint)."""
        from ctprobe.cli import build_config, create_parser

        args = create_parser().parse_args(["example.com", "--tor"])
        assert build_config(args).tor is True

    def test_empty_tor_endpoint_is_not_silently_disabled(self):
        """--tor "" must NOT coerce to None (fail-open); it must fail closed.

        Regression: an explicit routing request that resolves to an empty
        endpoint previously became None (routing disabled) and the scan ran
        DIRECT. The value must reach build_network_config, which fail-closes.
        """
        from ctprobe.cli import build_config, create_parser
        from ctprobe.network import build_network_config, NetworkError

        args = create_parser().parse_args(["example.com", "--tor", ""])
        config = build_config(args)
        assert config.tor == ""  # preserved, not coerced to None
        with pytest.raises(NetworkError):
            build_network_config(config.tor, config.proxy)


class TestHeaderSecurityAndPrecedence:
    """Header injection guard (Phase 44/45) and unified User-Agent precedence."""

    def test_crlf_in_header_value_rejected(self):
        from ctprobe.cli import parse_headers
        with pytest.raises(ValueError, match="control characters"):
            parse_headers(["X-Evil: value\r\nInjected: 1"])

    def test_crlf_in_header_name_rejected(self):
        from ctprobe.cli import parse_headers
        with pytest.raises(ValueError, match="control characters"):
            parse_headers(["Bad\rName: value"])

    def test_user_agent_with_crlf_rejected(self):
        from ctprobe.cli import create_parser, validate_arguments
        parser = create_parser()
        args = parser.parse_args(["example.com", "--user-agent", "UA\r\nEvil: 1"])
        with pytest.raises(SystemExit):
            validate_arguments(args, parser)

    def test_resolve_headers_default_user_agent(self):
        from ctprobe.http_client import resolve_headers
        out = resolve_headers({"Accept": "text/html"}, "MyUA/1.0")
        assert out["User-Agent"] == "MyUA/1.0"
        assert out["Accept"] == "text/html"

    def test_resolve_headers_explicit_header_wins(self):
        from ctprobe.http_client import resolve_headers
        out = resolve_headers({"User-Agent": "Explicit/2.0"}, "Default/1.0")
        assert out["User-Agent"] == "Explicit/2.0"

    def test_resolve_headers_no_duplicate_case_insensitive(self):
        """A lowercase user-provided UA must not produce a second UA header."""
        from ctprobe.http_client import resolve_headers
        out = resolve_headers({"user-agent": "Explicit/2.0"}, "Default/1.0")
        ua_keys = [k for k in out if k.lower() == "user-agent"]
        assert len(ua_keys) == 1
        assert out[ua_keys[0]] == "Explicit/2.0"

    def test_threaded_and_async_agree_on_user_agent(self):
        """Both engines resolve the same UA for the same inputs (no divergence)."""
        from ctprobe.http_client import resolve_headers
        base = {"User-Agent": "Explicit/9"}
        # http_client paths and async_engine._request_headers both delegate here.
        threaded = resolve_headers(base, "Default/1.0")

        from ctprobe.async_engine import AsyncLiveTester
        try:
            async_headers = AsyncLiveTester(
                headers=base, user_agent="Default/1.0"
            )._request_headers()
        except RuntimeError:
            pytest.skip("aiohttp not installed")
        assert threaded["User-Agent"] == async_headers["User-Agent"] == "Explicit/9"


class TestLogger:
    """Test logging utilities."""
    
    def test_logger_quiet_mode(self):
        """Test quiet mode suppresses output."""
        logger = Logger(quiet=True)
        # Should not raise, just not print
        logger.info("test message")
    
    def test_logger_verbose_mode(self):
        """Test verbose mode enables verbose messages."""
        logger = Logger(verbose=True, quiet=False)
        # Should not raise
        logger.verbose_msg("verbose message")
    
    def test_logger_debug_mode(self):
        """Test debug mode enables debug messages."""
        logger = Logger(debug=True, quiet=False)
        # Should not raise
        logger.debug_msg("debug message")


class TestSslEnvironment:
    """Test runtime TLS backend diagnostics."""

    @patch("ctprobe.environment.ssl.OPENSSL_VERSION", "LibreSSL 2.8.3")
    @patch("ctprobe.environment.ssl.OPENSSL_VERSION_INFO", (2, 8, 3, 0, 0))
    def test_libressl_warning_has_runtime_guidance_only(self, capsys):
        from ctprobe.environment import check_ssl_environment

        check_ssl_environment(Logger(use_color=False))
        output = capsys.readouterr().out

        assert "TLS backend: LibreSSL 2.8.3" in output
        assert "urllib3 v2 officially supports OpenSSL 1.1.1+" in output
        assert "requests[security]" not in output
        assert "Continuing with the current Python TLS environment." in output

    @patch("ctprobe.environment.ssl.OPENSSL_VERSION", "OpenSSL 3.0.12")
    @patch("ctprobe.environment.ssl.OPENSSL_VERSION_INFO", (3, 0, 12, 0, 0))
    def test_openssl_backend_is_informational(self, capsys):
        from ctprobe.environment import check_ssl_environment

        check_ssl_environment(Logger(use_color=False))
        output = capsys.readouterr().out

        assert "TLS backend: OpenSSL 3.0.12" in output
        assert "LibreSSL" not in output
        assert "urllib3 v2 officially supports" not in output

    def test_environment_detection_is_read_only_and_structured(self):
        from ctprobe.environment import detect_environment

        environment = detect_environment()

        assert environment.os_name
        assert environment.architecture
        assert environment.python_version
        assert environment.python_implementation
        assert environment.executable
        assert environment.tls_backend
        assert isinstance(environment.virtual_environment, bool)
        assert isinstance(environment.container, bool)
        assert isinstance(environment.wsl, bool)
        assert isinstance(environment.tty, bool)

    def test_portable_output_path_accepts_spaces_and_unicode(self):
        from ctprobe.output import make_simple_output_path

        path = make_simple_output_path(
            "nested results/scan", "résultats.json", "example.com", "json"
        )
        assert path.endswith("résultats.json")
        assert "nested results" in path


class TestRedactCredentials:
    """Test credential redaction."""
    
    def test_redact_proxy_credentials(self):
        """Test redacting proxy credentials."""
        url = "http://user:password@proxy.example:8080"
        redacted = redact_credentials(url)
        
        assert "password" not in redacted or "***" in redacted
        assert "proxy.example" in redacted
    
    def test_preserve_non_credential_urls(self):
        """Test preserving URLs without credentials."""
        url = "http://proxy.example:8080"
        redacted = redact_credentials(url)
        
        assert redacted == url


# Integration tests
class TestIntegration:
    """Integration tests for main workflow."""
    
    @patch("ctprobe.crt_client.requests.get")
    def test_end_to_end_discovery(self, mock_get):
        """Test end-to-end subdomain enumeration."""
        from ctprobe.crt_client import CRTClient
        
        # Mock CRT response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "example.com\nwww.example.com\napi.example.com"
        mock_get.return_value = mock_response
        
        client = CRTClient()
        domains, _ = client.fetch_domains("example.com")
        
        assert "example.com" in domains
        assert "www.example.com" in domains
        assert "api.example.com" in domains

    @patch("ctprobe.crt_client.requests.get")
    def test_crt_uses_encoded_apex_parameter(self, mock_get):
        from ctprobe.crt_client import CRTClient

        response = MagicMock(status_code=200, text="example.com")
        response.headers = {"content-type": "text/plain"}
        mock_get.return_value = response

        result = CRTClient().discover_domains("example.com")

        assert result.success
        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs["params"] == {"apex": "example.com"}
        assert mock_get.call_args.args[0] == "https://crt.name/v1/search"

    @patch("ctprobe.crt_client.requests.get")
    def test_crt_http_error_is_not_empty_success(self, mock_get):
        from ctprobe.crt_client import CRTClient

        response = MagicMock(status_code=400, text="invalid apex")
        response.headers = {"content-type": "text/plain"}
        mock_get.return_value = response

        result = CRTClient().discover_domains("www.example.com")

        assert not result.success
        assert result.status_code == 400
        assert result.domains == []
        assert result.error is not None
        assert "HTTP 400" in result.error

    @patch("ctprobe.main.CRTClient")
    def test_fetch_domains_filters_to_target_apex(self, mock_client_cls):
        """Only label-boundary subdomains of the target survive filtering."""
        from ctprobe.main import Scanner
        from ctprobe.models import ScanConfig, DiscoveryResult

        response = MagicMock()
        response.success = True
        response.domains = [
            "www.example.com",
            "api.example.com",
            "example.com",          # apex itself is a member
            "evil-example.com",     # suffix lookalike — must be dropped
            "example.net",          # unrelated TLD — must be dropped
            "other.org",            # unrelated — must be dropped
        ]
        mock_client_cls.return_value.discover_domains.return_value = response

        config = ScanConfig(target_domain="example.com")
        scanner = Scanner(config)
        result = scanner._fetch_domains("example.com")

        assert result == ["api.example.com", "example.com", "www.example.com"]


class TestNetworkConfig:
    """Proxy/Tor endpoint parsing, redaction, and SOCKS capability."""

    def test_disabled_when_no_routing(self):
        from ctprobe.network import build_network_config
        cfg = build_network_config(tor=None, proxy=None)
        assert cfg.enabled is False
        assert cfg.proxies is None

    def test_bare_tor_uses_default_endpoint(self):
        from ctprobe.network import build_network_config
        cfg = build_network_config(tor=True)
        assert cfg.is_tor is True
        assert cfg.scheme == "socks5h"
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 9050
        assert cfg.proxies == {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }

    def test_display_url_redacts_credentials(self):
        from ctprobe.network import build_network_config
        cfg = build_network_config(tor="socks5://user:secret@127.0.0.1:9050")
        display_url = cfg.display_url
        proxies = cfg.proxies
        assert display_url is not None and proxies is not None
        assert "secret" not in display_url
        assert "user:***@127.0.0.1:9050" in display_url
        # The actual proxies value keeps credentials so auth still works.
        assert "secret" in proxies["https"]

    def test_tor_and_proxy_conflict(self):
        from ctprobe.network import build_network_config, NetworkError
        with pytest.raises(NetworkError):
            build_network_config(tor=True, proxy="http://127.0.0.1:8080")

    def test_unsupported_scheme_rejected(self):
        from ctprobe.network import build_network_config, NetworkError
        with pytest.raises(NetworkError, match="Unsupported"):
            build_network_config(proxy="ftp://127.0.0.1:21")

    def test_proxy_requires_port(self):
        from ctprobe.network import build_network_config, NetworkError
        with pytest.raises(NetworkError, match="port"):
            build_network_config(proxy="http://127.0.0.1")

    def test_socks_capability_error_when_pysocks_missing(self):
        from ctprobe import network
        from ctprobe.network import build_network_config, NetworkError
        with patch.object(network, "_socks_available", return_value=False):
            with pytest.raises(NetworkError, match="PySocks"):
                build_network_config(tor=True)


class TestNetworkVerification:
    """Fail-closed verification: SOCKS reachability + genuine Tor confirmation."""

    def _tor_config(self):
        from ctprobe.network import build_network_config
        return build_network_config(tor="socks5h://127.0.0.1:9050")

    def test_disabled_config_is_ready(self):
        from ctprobe.network import NetworkConfig, verify
        assert verify(NetworkConfig(proxies=None, is_tor=False)) is True

    def test_unreachable_socks_fails(self):
        from ctprobe import network
        with patch.object(network, "_socks_reachable", return_value=False):
            assert network.verify(self._tor_config()) is False

    def test_reachable_but_not_tor_fails_under_tor(self):
        from ctprobe import network
        response = MagicMock()
        response.json.return_value = {"IsTor": False, "IP": "1.2.3.4"}
        with patch.object(network, "_socks_reachable", return_value=True), \
             patch.object(network.requests, "get", return_value=response):
            assert network.verify(self._tor_config()) is False

    def test_tor_confirmed_is_ready(self):
        from ctprobe import network
        response = MagicMock()
        response.json.return_value = {"IsTor": True, "IP": "9.9.9.9"}
        with patch.object(network, "_socks_reachable", return_value=True), \
             patch.object(network.requests, "get", return_value=response):
            assert network.verify(self._tor_config()) is True

    def test_connectivity_exception_fails_closed(self):
        from ctprobe import network
        import requests as real_requests
        with patch.object(network, "_socks_reachable", return_value=True), \
             patch.object(network.requests, "get",
                          side_effect=real_requests.RequestException("boom")):
            assert network.verify(self._tor_config()) is False


class TestFailClosedOrchestration:
    """--tor verification failure must stop the scan before CRT discovery."""

    def test_tor_failure_exits_and_skips_crt(self):
        from ctprobe.main import Scanner
        from ctprobe.models import ScanConfig
        from ctprobe import main as main_module

        config = ScanConfig(target_domain="example.com", tor=True, quiet=True)
        scanner = Scanner(config)

        with patch.object(main_module, "verify", return_value=False) as mock_verify, \
             patch.object(Scanner, "_fetch_domains") as mock_fetch:
            with pytest.raises(SystemExit) as exc:
                scanner.run()
        assert exc.value.code != 0
        mock_verify.assert_called_once()
        mock_fetch.assert_not_called()


class TestCrtRouting:
    """CRT discovery must route through the shared proxy (no IP leak)."""

    @patch("ctprobe.crt_client.requests.get")
    def test_crt_passes_proxies(self, mock_get):
        from ctprobe.crt_client import CRTClient
        response = MagicMock(status_code=200, text="example.com")
        response.headers = {"content-type": "text/plain"}
        mock_get.return_value = response

        proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        CRTClient(proxies=proxies).discover_domains("example.com")

        assert mock_get.call_args.kwargs["proxies"] == proxies


class TestHttpVersionPolicy:
    """--force / --http-version selection and capability handling."""

    def test_force_without_explicit_version_rejected(self):
        from ctprobe.cli import create_parser, validate_arguments
        parser = create_parser()
        args = parser.parse_args(["example.com", "--force"])
        with pytest.raises(SystemExit):
            validate_arguments(args, parser)

    def test_force_with_explicit_version_allowed(self):
        from ctprobe.cli import create_parser, validate_arguments
        parser = create_parser()
        args = parser.parse_args(["example.com", "--http-version", "2", "--force"])
        validate_arguments(args, parser)  # no raise

    def test_protocol_order_force_pins_version(self):
        from ctprobe.http_client import HTTPClient
        assert HTTPClient._protocol_order("2", True) == ["2"]
        assert HTTPClient._protocol_order("2", False) == ["2", "1.1"]
        assert HTTPClient._protocol_order("auto", False) == ["3", "2", "1.1"]

    def test_forced_unavailable_protocol_raises_protocol_error(self):
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient, HTTPClientError
        client = HTTPClient()
        with patch.object(http_client, "_httpx_http2_available", return_value=False):
            with pytest.raises(HTTPClientError) as exc:
                client.request("https://example.com", http_version="2", force=True)
        assert exc.value.error_type == ErrorType.PROTOCOL_ERROR

    @staticmethod
    def _fake_httpx(negotiated="HTTP/2", record=None):
        """A minimal fake httpx module whose stream() reports ``negotiated``.

        The fake response raises if the body is read, proving _request_http2
        only ever touches status/headers/version metadata (spec §36).
        """
        class _Resp:
            status_code = 200
            url = "https://example.com/"
            http_version = negotiated
            headers = {"server": "nginx", "content-type": "text/html"}
            history = []

            def read(self):  # pragma: no cover - must never be called
                raise AssertionError("HTTP/2 path downloaded the body")

        class _StreamCtx:
            def __enter__(_self):
                return _Resp()

            def __exit__(_self, *a):
                return False

        class _Client:
            def __init__(_self, **kwargs):
                if record is not None:
                    record.update(kwargs)

            def __enter__(_self):
                return _self

            def __exit__(_self, *a):
                return False

            def stream(_self, method, url):
                return _StreamCtx()

        module = types.ModuleType("httpx")
        module.__dict__["Client"] = _Client
        return module

    def test_http2_reports_actual_negotiated_version(self):
        """http2=True that negotiates HTTP/1.1 must report HTTP/1.1, not a lie."""
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient
        fake = self._fake_httpx(negotiated="HTTP/1.1")
        with patch.object(http_client, "_httpx_http2_available", return_value=True), \
                patch.dict(sys.modules, {"httpx": fake}):
            result = HTTPClient().request("https://example.com", http_version="2")
        assert result["http_version"] == "HTTP/1.1"

    def test_force_http2_rejects_downgrade_to_http11(self):
        """--force --http-version 2 must fail closed when the wire is HTTP/1.1."""
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient, HTTPClientError
        fake = self._fake_httpx(negotiated="HTTP/1.1")
        with patch.object(http_client, "_httpx_http2_available", return_value=True), \
                patch.dict(sys.modules, {"httpx": fake}):
            with pytest.raises(HTTPClientError) as exc:
                HTTPClient().request("https://example.com", http_version="2", force=True)
        assert exc.value.error_type == ErrorType.PROTOCOL_ERROR

    def test_force_http2_accepts_genuine_http2(self):
        """--force --http-version 2 succeeds when HTTP/2 is actually negotiated."""
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient
        fake = self._fake_httpx(negotiated="HTTP/2")
        with patch.object(http_client, "_httpx_http2_available", return_value=True), \
                patch.dict(sys.modules, {"httpx": fake}):
            result = HTTPClient().request("https://example.com", http_version="2", force=True)
        assert result["http_version"] == "HTTP/2"
        assert result["status_code"] == 200

    def test_http3_reports_effective_url_and_redirects(self):
        """The curl HTTP/3 path must report the followed URL and redirect count,
        discard the body, and guard against argument injection."""
        import subprocess
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient

        captured = {}

        def fake_run(command, **kwargs):
            captured["command"] = command
            result = MagicMock()
            result.returncode = 0
            # -w trailer: status, time_total, num_redirects, url_effective
            result.stdout = "301\n0.123\n2\nhttps://final.example.com/landing"
            result.stderr = ""
            return result

        with patch.object(http_client.shutil, "which", return_value="/usr/bin/curl"), \
                patch.object(subprocess, "run", side_effect=fake_run):
            result = HTTPClient()._request_http3("https://example.com")

        assert result["http_version"] == "HTTP/3"
        assert result["status_code"] == 301
        assert result["final_url"] == "https://final.example.com/landing"
        assert result["redirect_count"] == 2

        command = captured["command"]
        # Body is discarded to os.devnull (reachability only, no buffering).
        assert "--output" in command
        assert os.devnull in command
        # Redirects are bounded.
        assert "--max-redirs" in command
        # The URL is passed after a "--" end-of-options guard.
        assert command[-2:] == ["--", "https://example.com"]

    def test_http3_rejects_truncated_trailer(self):
        """A short/garbled curl trailer must raise, not silently mis-parse."""
        import subprocess
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient, HTTPClientError

        def fake_run(command, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "200\n0.1"  # only 2 lines, missing redirects/url
            result.stderr = ""
            return result

        with patch.object(http_client.shutil, "which", return_value="/usr/bin/curl"), \
                patch.object(subprocess, "run", side_effect=fake_run):
            with pytest.raises(HTTPClientError):
                HTTPClient()._request_http3("https://example.com")


class TestSchemeFallbackAndErrors:
    """Scheme fallback is independent of --force; errors carry a type."""

    def test_force_still_allows_scheme_fallback(self):
        from ctprobe.live_test import LiveTester
        from ctprobe.http_client import HTTPClientError

        ok_response = {
            "status_code": 200, "final_url": "http://example.com/",
            "http_version": "HTTP/1.1", "headers": {}, "response_time_ms": 1.0,
            "server": None, "content_type": None, "redirect_count": 0,
        }

        calls = []

        def fake_request(self, url, http_version="auto", force=False, method="GET"):
            calls.append(url)
            if url.startswith("https://"):
                raise HTTPClientError("TLS error", ErrorType.TLS_ERROR)
            return ok_response

        with patch("ctprobe.live_test.HTTPClient.request", new=fake_request):
            result = LiveTester().test_domain("example.com", http_version="2", force=True)

        # https attempted first, then http fallback despite force.
        assert calls == ["https://example.com", "http://example.com"]
        assert result.http_response_received is True
        assert result.status_code == 200

    def test_error_type_propagates_from_requests_timeout(self):
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient, HTTPClientError
        import requests as real_requests

        session = MagicMock()
        session.request.side_effect = real_requests.exceptions.Timeout("slow")
        with patch.object(http_client.requests, "Session", return_value=session):
            client = HTTPClient()
            with pytest.raises(HTTPClientError) as exc:
                client.request("https://example.com", http_version="1.1")
        assert exc.value.error_type == ErrorType.CONNECTION_TIMEOUT

    def test_error_type_propagates_from_ssl_error(self):
        from ctprobe import http_client
        from ctprobe.http_client import HTTPClient, HTTPClientError
        import requests as real_requests

        session = MagicMock()
        session.request.side_effect = real_requests.exceptions.SSLError("bad cert")
        with patch.object(http_client.requests, "Session", return_value=session):
            client = HTTPClient()
            with pytest.raises(HTTPClientError) as exc:
                client.request("https://example.com", http_version="1.1")
        assert exc.value.error_type == ErrorType.TLS_ERROR


class _FakeVersion:
    def __init__(self, major=1, minor=1):
        self.major = major
        self.minor = minor


class _FakeResp:
    def __init__(self, status, url, history=(), headers=None, version=(1, 1)):
        self.status = status
        self.url = url
        self.history = list(history)
        self.headers = headers or {}
        self.version = _FakeVersion(*version)
        self.body_read = False

    async def read(self):  # pragma: no cover - must never be called
        self.body_read = True
        raise AssertionError("engine downloaded the response body")

    async def text(self):  # pragma: no cover - must never be called
        raise AssertionError("engine downloaded the response body")


class _FakeCtx:
    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc

    async def __aenter__(self):
        if self._exc is not None:
            raise self._exc
        return self._resp

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, router):
        self._router = router
        self.closed = False
        self.get_calls = []

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return self._router(url, kwargs)

    async def close(self):
        self.closed = True


def _run_engine(tester, domains, workers=4, progress=None, router=None):
    """Run AsyncLiveTester.run with aiohttp's session constructors mocked."""
    import asyncio as _asyncio
    from unittest.mock import patch as _patch, MagicMock as _MM
    from ctprobe import async_engine

    fake_session = _FakeSession(router)
    with _patch.object(async_engine.aiohttp, "TCPConnector", return_value=_MM()), \
         _patch.object(async_engine.aiohttp, "ClientTimeout", return_value=_MM()), \
         _patch.object(async_engine.aiohttp, "ClientSession", return_value=fake_session):
        results = _asyncio.run(tester.run(domains, workers, progress))
    return results, fake_session


class TestAsyncEngineRouting:
    """live_test dispatcher chooses async vs threaded correctly."""

    def test_proxy_url_and_socks_detection(self):
        from ctprobe.live_test import _proxy_url, _is_socks_route

        assert _proxy_url(None) is None
        assert _proxy_url({"http": "http://p:8080", "https": "http://p:8080"}) == "http://p:8080"
        assert _is_socks_route(None) is False
        assert _is_socks_route({"http": "http://p:8080", "https": "http://p:8080"}) is False
        assert _is_socks_route(
            {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        ) is True

    def _dispatch(self, http_version="auto", proxies=None, aiohttp_ok=True):
        from ctprobe.live_test import LiveTester

        marker = [LiveTestResult(domain="async.example", live=True)]
        seen = {}

        def fake_async(self, **kwargs):
            seen["async"] = kwargs
            return marker

        ok_response = {
            "status_code": 200, "final_url": "https://x/", "http_version": "HTTP/1.1",
            "headers": {}, "response_time_ms": 1.0, "server": None,
            "content_type": None, "redirect_count": 0,
        }

        def fake_request(self, url, http_version="auto", force=False, method="GET"):
            return ok_response

        with patch("ctprobe.live_test.LiveTester._run_async", new=fake_async), \
             patch("ctprobe.live_test._aiohttp_available", return_value=aiohttp_ok), \
             patch("ctprobe.live_test.HTTPClient.request", new=fake_request):
            results = LiveTester().test_domains(
                ["a.example"], workers=5, http_version=http_version, proxies=proxies,
            )
        used_async = "async" in seen
        return used_async, seen.get("async"), results

    def test_auto_direct_uses_async(self):
        used_async, _, results = self._dispatch(http_version="auto")
        assert used_async is True
        assert results is not None and results[0].domain == "async.example"

    def test_http11_direct_uses_async(self):
        used_async, _, _ = self._dispatch(http_version="1.1")
        assert used_async is True

    def test_http2_uses_threaded(self):
        used_async, _, _ = self._dispatch(http_version="2")
        assert used_async is False

    def test_http3_uses_threaded(self):
        used_async, _, _ = self._dispatch(http_version="3")
        assert used_async is False

    def test_socks_route_uses_threaded(self):
        proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        used_async, _, _ = self._dispatch(http_version="auto", proxies=proxies)
        assert used_async is False

    def test_aiohttp_absent_uses_threaded(self):
        used_async, _, _ = self._dispatch(http_version="auto", aiohttp_ok=False)
        assert used_async is False

    def test_stealth_caps_effective_concurrency(self):
        used_async, kwargs, _ = self._dispatch_stealth()
        assert used_async is True
        assert kwargs is not None
        assert kwargs["effective_workers"] <= 3

    def _dispatch_stealth(self):
        from ctprobe.live_test import LiveTester

        seen = {}

        def fake_async(self, **kwargs):
            seen["async"] = kwargs
            return []

        with patch("ctprobe.live_test.LiveTester._run_async", new=fake_async), \
             patch("ctprobe.live_test._aiohttp_available", return_value=True):
            LiveTester().test_domains(
                ["a.example"], workers=30, http_version="auto", stealth=True,
            )
        return "async" in seen, seen.get("async"), None


class TestAsyncEngine:
    """AsyncLiveTester behavior via a mocked ClientSession."""

    def _tester(self, **kwargs):
        from ctprobe.async_engine import AsyncLiveTester

        defaults: dict = dict(match_codes=frozenset({200}), filter_codes=frozenset())
        defaults.update(kwargs)
        return AsyncLiveTester(**defaults)

    def test_matched_200(self):
        def router(url, kw):
            return _FakeCtx(_FakeResp(200, url, headers={"Server": "nginx"}))

        results, session = _run_engine(self._tester(), ["a.example"], router=router)
        r = results[0]
        assert r.status_code == 200
        assert r.live is True and r.status_matched is True
        assert r.http_version == "HTTP/1.1"
        assert r.scheme == "https"
        assert r.server == "nginx"
        assert session.closed is True

    def test_filtered_beats_matched(self):
        tester = self._tester(match_codes=frozenset({200, 204}), filter_codes=frozenset({204}))

        def router(url, kw):
            return _FakeCtx(_FakeResp(204, url))

        results, _ = _run_engine(tester, ["a.example"], router=router)
        r = results[0]
        assert r.status_filtered is True
        assert r.status_matched is False
        assert r.live is False

    def test_unmatched_404(self):
        def router(url, kw):
            return _FakeCtx(_FakeResp(404, url))

        results, _ = _run_engine(self._tester(), ["a.example"], router=router)
        r = results[0]
        assert r.http_response_received is True
        assert r.status_matched is False and r.status_filtered is False
        assert r.live is False

    def test_scheme_fallback_https_to_http(self):
        import aiohttp

        def router(url, kw):
            if url.startswith("https://"):
                return _FakeCtx(exc=aiohttp.ClientError("tls down"))
            return _FakeCtx(_FakeResp(200, url))

        results, _ = _run_engine(self._tester(), ["a.example"], router=router)
        r = results[0]
        assert r.status_code == 200
        assert r.scheme == "http"

    def test_redirect_count_and_final_url(self):
        def router(url, kw):
            return _FakeCtx(_FakeResp(
                200, "https://a.example/final", history=[object(), object()]
            ))

        results, _ = _run_engine(self._tester(), ["a.example"], router=router)
        r = results[0]
        assert r.redirect_count == 2
        assert r.final_url == "https://a.example/final"

    def test_both_schemes_fail_no_response(self):
        import aiohttp

        def router(url, kw):
            return _FakeCtx(exc=aiohttp.ClientError("refused"))

        results, session = _run_engine(self._tester(), ["a.example"], router=router)
        r = results[0]
        assert r.http_response_received is False
        assert r.live is False
        assert r.error_type == ErrorType.CONNECTION_ERROR
        assert session.closed is True

    def test_results_sorted_and_session_closed(self):
        def router(url, kw):
            return _FakeCtx(_FakeResp(200, url))

        results, session = _run_engine(
            self._tester(), ["c.example", "a.example", "b.example"], workers=2, router=router
        )
        assert [r.domain for r in results] == ["a.example", "b.example", "c.example"]
        assert session.closed is True


class TestAsyncErrorMapping:
    """Transport exceptions map to structured ErrorType values."""

    def _dummy(self, base, msg=""):
        class _D(base):
            def __init__(self):
                pass

            def __str__(self):
                return msg

        return _D()

    def test_timeout(self):
        import asyncio
        from ctprobe.async_engine import _map_error

        assert _map_error(asyncio.TimeoutError()) == ErrorType.CONNECTION_TIMEOUT

    def test_ssl(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(self._dummy(aiohttp.ClientSSLError)) == ErrorType.TLS_ERROR

    def test_certificate(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(
            self._dummy(aiohttp.ClientConnectorCertificateError)
        ) == ErrorType.TLS_ERROR

    def test_proxy(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(
            self._dummy(aiohttp.ClientProxyConnectionError)
        ) == ErrorType.PROXY_ERROR

    def test_invalid_url(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(self._dummy(aiohttp.InvalidURL)) == ErrorType.INVALID_URL

    def test_connector_dns(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(
            self._dummy(aiohttp.ClientConnectorError, "getaddrinfo failed")
        ) == ErrorType.DNS_ERROR

    def test_connector_connection(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(
            self._dummy(aiohttp.ClientConnectorError, "connection refused")
        ) == ErrorType.CONNECTION_ERROR

    def test_generic_client_error(self):
        import aiohttp
        from ctprobe.async_engine import _map_error

        assert _map_error(aiohttp.ClientError()) == ErrorType.CONNECTION_ERROR


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
