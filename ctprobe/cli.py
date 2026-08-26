"""Command-line interface and configuration."""

import argparse

from . import __version__
from .models import ScanConfig
from .status_policy import DEFAULT_MATCH_CODES, StatusCodeError, parse_status_codes


def create_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ctprobe",
        description=(
            "Certificate Transparency subdomain enumeration and HTTP/S reconnaissance tool.\n\n"
            "Query crt.name for SSL certificates, enumerate certificate-derived "
            "subdomains of a target domain, and test their HTTP/S reachability."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ctprobe {__version__}",
    )

    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain (e.g., example.com)",
    )
    
    # Discovery options
    parser.add_argument(
        "--live",
        action="store_true",
        help="Automatically perform live testing on discovered subdomains.",
    )
    
    parser.add_argument(
        "--no-live",
        action="store_true",
        help="Skip live testing (default: ask interactively).",
    )
    
    # Network options
    parser.add_argument(
        "--proxy",
        help="HTTP/S proxy URL (e.g., http://127.0.0.1:8080).",
    )
    
    parser.add_argument(
        "--tor",
        nargs="?",
        const=True,
        help=(
            "Route through Tor.\n"
            "Optional: specify SOCKS proxy URL.\n"
            "Default: socks5h://127.0.0.1:9050"
        ),
    )
    
    # HTTP options
    parser.add_argument(
        "--http-version",
        choices=["auto", "1.1", "2", "3"],
        default="auto",
        help=(
            "HTTP protocol version:\n"
            "  auto - Try HTTP/3 → HTTP/2 → HTTP/1.1 (default)\n"
            "  1.1  - HTTP/1.1 only\n"
            "  2    - HTTP/2 only\n"
            "  3    - HTTP/3 only"
        ),
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Force selected HTTP version without fallback.\n"
            "If --http-version 2 --force, use HTTP/2 only (fail if unavailable)."
        ),
    )
    
    # TLS options
    parser.add_argument(
        "--bypass-ssl",
        "--bypass-tls",
        dest="bypass_tls",
        action="store_true",
        help=(
            "Disable TLS certificate verification.\n"
            "Warning: This is insecure and only for authorized testing."
        ),
    )
    
    # Request options
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help=(
            "Custom HTTP header (can be repeated).\n"
            'Example: --header "Accept: text/html" --header "X-Test: value"'
        ),
    )
    
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0",
        help="Custom User-Agent header (default: Mozilla/5.0).",
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0).",
    )
    
    # Concurrency and performance
    parser.add_argument(
        "--workers",
        type=int,
        default=30,
        help="Number of concurrent workers (default: 30).",
    )
    
    # Stealth/rate-limiting options
    parser.add_argument(
        "--stealth",
        action="store_true",
        help=(
            "Low-rate conservative scanning mode.\n"
            "Reduces concurrency, adds randomized delays, respects rate limiting.\n"
            "NOT undetectable or anonymous - just reduces network load."
        ),
    )
    
    parser.add_argument(
        "--stealth-min-delay",
        type=float,
        default=1.0,
        help="Minimum stealth delay in seconds (default: 1.0).",
    )
    
    parser.add_argument(
        "--stealth-max-delay",
        type=float,
        default=3.0,
        help="Maximum stealth delay in seconds (default: 3.0).",
    )
    
    # Threat analysis
    parser.add_argument(
        "--threat",
        action="store_true",
        help=(
            "Run basic threat heuristics on discovered subdomains.\n"
            "Analyzes TLDs, keywords, structure (heuristic only, not authoritative)."
        ),
    )

    parser.add_argument(
        "-mc", "--match-code",
        default=None,
        metavar="MATCH_CODE",
        help=(
            "Match HTTP status codes, or 'all'. Supports codes, comma-separated "
            "values, and ranges. Supplying this option automatically enables "
            "HTTP testing. Default: 200-299,301,302,307,401,403,405,500."
        ),
    )

    parser.add_argument(
        "-fc", "--filter-code",
        default=None,
        metavar="FILTER_CODE",
        help=(
            "Exclude HTTP status codes from matching responses. Supports codes, "
            "comma-separated values, and ranges. Supplying this option "
            "automatically enables HTTP testing."
        ),
    )
    
    # Output options
    parser.add_argument(
        "--output",
        choices=["txt", "json", "xls", "xlsx"],
        default="txt",
        help=(
            "Output format:\n"
            "  txt  - Plain text (default)\n"
            "  json - JSON\n"
            "  xlsx - Excel spreadsheet"
        ),
    )
    
    parser.add_argument(
        "-f",
        "--filename",
        help=(
            "Custom output filename/base name.\n"
            "With --live, creates: filename.ALL-output.ext and filename.LIVE-output.ext\n"
            "Without --live, creates: filename.output.ext"
        ),
    )
    
    parser.add_argument(
        "--output-dir",
        default="Outputs",
        help="Output directory (default: Outputs, created if needed).",
    )
    
    # Verbosity
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress and live test results.",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show debugging information and errors.",
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimize console output.",
    )
    
    # Color/terminal options
    parser.add_argument(
        "--no-color",
        action="store_true",
        help=(
            "Disable colored output.\n"
            "Also respected via NO_COLOR environment variable."
        ),
    )
    
    return parser


def validate_arguments(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate parsed arguments, exit with error if invalid."""

    if args.workers < 1:
        parser.error("--workers must be at least 1.")

    # The User-Agent becomes an HTTP header; reject control characters so it
    # cannot be used for header injection (Phase 44/45).
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in args.user_agent):
        parser.error("--user-agent must not contain control characters.")
    
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0.")

    if args.stealth_min_delay < 0:
        parser.error("--stealth-min-delay cannot be negative.")
    
    if args.stealth_max_delay < 0:
        parser.error("--stealth-max-delay cannot be negative.")
    
    if args.stealth_max_delay < args.stealth_min_delay:
        parser.error(
            "--stealth-max-delay must be >= --stealth-min-delay."
        )
    
    if args.live and args.no_live:
        parser.error("--live and --no-live cannot be used together.")

    if args.no_live and (args.match_code is not None or args.filter_code is not None):
        parser.error(
            "--match-code/--filter-code require HTTP testing and cannot be combined "
            "with --no-live."
        )
    
    if args.proxy and args.tor is not None:
        parser.error(
            "--proxy and --tor cannot be used together. "
            "Choose one routing method."
        )
    
    if args.http_version not in ["auto", "1.1", "2", "3"]:
        parser.error(f"Invalid --http-version: {args.http_version}")

    # --force pins a *selected* protocol version; it is meaningless (and
    # contradictory) with auto, which is defined by fallback.
    if args.force and args.http_version == "auto":
        parser.error(
            "--force requires an explicit --http-version (1.1, 2, or 3); "
            "it cannot be combined with auto."
        )

    try:
        match_codes = (
            DEFAULT_MATCH_CODES if args.match_code is None
            else parse_status_codes(args.match_code)
        )
        filter_codes = (
            frozenset() if args.filter_code is None
            else parse_status_codes(args.filter_code)
        )
    except StatusCodeError as exc:
        parser.error(str(exc))

    if not match_codes - filter_codes:
        parser.error("--filter-code removes all status codes from --match-code.")


def parse_headers(header_strings: list) -> dict:
    """
    Parse custom headers from command-line format.
    
    Format: "Name: Value"
    """
    headers = {}
    
    for header_str in (header_strings or []):
        if ":" not in header_str:
            raise ValueError(f"Invalid header format: {header_str!r}. Expected 'Name: Value'.")

        name, value = header_str.split(":", 1)
        name = name.strip()
        value = value.strip()

        if not name:
            raise ValueError(f"Empty header name in: {header_str!r}")

        # Reject CR/LF (and other control characters) to prevent HTTP header /
        # request-line injection via a crafted --header value (Phase 44/45).
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name + value):
            raise ValueError(
                f"Header contains control characters (possible injection): {header_str!r}"
            )

        headers[name] = value

    return headers


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Build ScanConfig from parsed arguments."""

    match_requested = args.match_code is not None
    filter_requested = args.filter_code is not None
    live_testing = args.live or match_requested or filter_requested

    try:
        headers = parse_headers(args.header)
    except ValueError as exc:
        raise ValueError(f"Invalid header specification: {exc}")

    try:
        match_codes = (
            DEFAULT_MATCH_CODES if args.match_code is None
            else parse_status_codes(args.match_code)
        )
        filter_codes = (
            frozenset() if args.filter_code is None
            else parse_status_codes(args.filter_code)
        )
    except StatusCodeError as exc:
        raise ValueError(str(exc)) from exc

    if not match_codes - filter_codes:
        raise ValueError("--filter-code removes all status codes from --match-code.")
    
    return ScanConfig(
        target_domain=args.domain,
        perform_live_test=live_testing,
        live_mode=True if live_testing else False if args.no_live else None,
        match_code_requested=match_requested,
        filter_code_requested=filter_requested,
        match_code_expression=args.match_code.strip() if args.match_code else None,
        filter_code_expression=args.filter_code.strip() if args.filter_code else None,
        http_version=args.http_version,
        workers=args.workers,
        timeout=args.timeout,
        proxy=args.proxy,
        # Pass --tor through unchanged: None (disabled), True (bare --tor, default
        # endpoint), or an explicit endpoint string. Do NOT coerce a falsy-but-
        # present value (e.g. --tor "") to None — that would silently disable an
        # explicit routing request and run direct (fail-open). An empty endpoint
        # must reach build_network_config, which fail-closes with NetworkError.
        tor=args.tor,
        bypass_tls=args.bypass_tls,
        stealth=args.stealth,
        stealth_min_delay=args.stealth_min_delay,
        stealth_max_delay=args.stealth_max_delay,
        threat_analysis=args.threat,
        output_format=args.output,
        output_dir=args.output_dir,
        custom_filename=args.filename,
        force=args.force,
        verbose=args.verbose,
        debug=args.debug,
        quiet=args.quiet,
        no_color=args.no_color,
        headers=headers,
        user_agent=args.user_agent,
        match_codes=match_codes,
        filter_codes=filter_codes,
    )
