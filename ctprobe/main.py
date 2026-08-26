"""Main scanner orchestration."""

import sys
import time
from typing import List, Optional

from .cli import create_parser, validate_arguments, build_config
from .logging_utils import Logger
from .domain import (
    deduplicate_domains,
    get_registrable_domain,
    is_subdomain_of,
    normalize_domain,
    normalize_wildcard,
)
from .crt_client import CRTClient, CRTError
from .live_test import LiveTester
from .threat import analyze_threat
from .output import (
    save_live_test_output,
    save_discovery_output,
)
from .models import ScanConfig
from .environment import check_ssl_environment
from .status_policy import format_status_codes
from .network import NetworkConfig, NetworkError, build_network_config, verify
from .http_client import check_protocol_capability


class Scanner:
    """Main scanner orchestrator."""
    
    def __init__(self, config: ScanConfig, logger: Optional[Logger] = None):
        self.config = config
        self.logger = logger or Logger(
            verbose=config.verbose,
            debug=config.debug,
            quiet=config.quiet,
            use_color=not config.no_color,
        )
        self.network: NetworkConfig = NetworkConfig(proxies=None, is_tor=False)
    
    def run(self) -> None:
        """Execute the scan."""
        start_time = time.monotonic()
        
        try:
            check_ssl_environment(self.logger)

            domain = self._get_and_validate_domain()
            
            if not domain:
                self.logger.error("Invalid target domain.")
                sys.exit(1)
            
            self.logger.info(f"[*] Target: {domain}")
            crt_target = get_registrable_domain(domain)
            self.logger.info(f"[*] CT discovery target: {crt_target}")
            self.logger.info(f"[*] HTTP version: {self.config.http_version}")
            
            if self.config.force:
                self.logger.info("[*] Force mode enabled (no protocol-version fallback).")
                # Surface a forced-but-unavailable protocol once, before scanning.
                ok, reason = check_protocol_capability(self.config.http_version)
                if not ok:
                    self.logger.error(
                        f"HTTP/{self.config.http_version} was explicitly forced but "
                        f"is unavailable: {reason}"
                    )
                    sys.exit(2)

            # Build the single, shared network configuration and (for Tor/proxy)
            # verify it BEFORE any scan traffic. Routing is fail-closed: if
            # verification fails we never fall back to a direct connection.
            try:
                self.network = build_network_config(self.config.tor, self.config.proxy)
            except NetworkError as exc:
                self.logger.error(str(exc))
                sys.exit(2)

            if self.network.enabled:
                label = "Tor" if self.network.is_tor else "Proxy"
                self.logger.info(f"[*] {label}: {self.network.display_url}")
                if not verify(self.network, timeout=self.config.timeout, logger=self.logger):
                    self.logger.error(
                        "Network routing could not be verified; refusing to run "
                        "(fail-closed). Direct fallback is disabled."
                    )
                    sys.exit(2)

            if self.config.stealth:
                self.logger.info("[*] Stealth mode enabled (low-rate scanning).")
                self.logger.info(
                    f"[*] Delay: {self.config.stealth_min_delay:.2f}-"
                    f"{self.config.stealth_max_delay:.2f}s"
                )
            
            self.logger.info("[*] Querying Certificate Transparency...")
            domains = self._fetch_domains(crt_target)
            
            if domains is None:
                self.logger.error("CRT discovery could not be completed.")
                sys.exit(1)

            if not domains:
                self.logger.error("No subdomains found.")
                sys.exit(1)

            count = len(domains)
            noun = "subdomain" if count == 1 else "subdomains"
            self.logger.info(f"[+] Found {count} unique {noun}.")

            self._display_status_configuration()
            
            perform_live_test = self._should_perform_live_test()
            
            if perform_live_test:
                if self.config.match_code_requested or self.config.filter_code_requested:
                    reasons = []
                    if self.config.match_code_requested:
                        reasons.append("--match-code")
                    if self.config.filter_code_requested:
                        reasons.append("--filter-code")
                    self.logger.info(
                        "[*] HTTP testing automatically enabled by "
                        f"{' and '.join(reasons)}."
                    )
                self._perform_live_test(domain, domains, start_time)
            else:
                self._save_discovery_results(domain, domains, start_time)
        
        except KeyboardInterrupt:
            self.logger.error("\n[!] Interrupted by user.")
            sys.exit(130)
        
        except Exception as exc:
            self.logger.error(f"Fatal error: {exc}")
            if self.config.debug:
                raise
            sys.exit(1)
    
    def _get_and_validate_domain(self) -> str:
        """Get and validate the target domain."""
        domain = self.config.target_domain
        
        if not domain:
            try:
                domain = input("[?] Enter domain: ").strip()
            except KeyboardInterrupt:
                self.logger.error("\n[!] Interrupted by user.")
                sys.exit(130)
        
        domain = normalize_domain(domain)
        return domain
    
    def _fetch_domains(self, domain: str) -> Optional[List[str]]:
        """Fetch subdomains of the target from Certificate Transparency."""
        client = CRTClient(
            timeout=self.config.timeout,
            logger=self.logger,
            proxies=self.network.proxies,
        )

        try:
            discovery = client.discover_domains(domain)
        except CRTError as exc:
            self.logger.error(f"Certificate Transparency request failed: {exc}")
            return None

        if not discovery.success:
            self.logger.error(f"Certificate Transparency request failed: {discovery.error}")
            return None

        # CT responses can contain names outside the target apex (sibling or
        # unrelated SANs). Filter with label-aware matching so the reported
        # results really are subdomains of the target, not arbitrary
        # certificate DNS names.
        raw_domains = list(discovery.domains)

        normalized = []
        for d in raw_domains:
            d = normalize_wildcard(d)
            d = normalize_domain(d)
            if d and is_subdomain_of(d, domain):
                normalized.append(d)

        unique_domains = deduplicate_domains(normalized)

        return unique_domains
    
    def _should_perform_live_test(self) -> bool:
        """Determine if live testing should be performed."""
        if self.config.live_mode is not None:
            return self.config.live_mode

        if self.config.quiet:
            return False
        
        # Ask interactively if no --live or --no-live
        if not hasattr(self.config, '_interactive_choice_made'):
            try:
                choice = input(
                    "[?] Do you want to test which subdomains are live? [y/n]: "
                ).strip().lower()
            except KeyboardInterrupt:
                self.logger.error("\n[!] Interrupted by user.")
                sys.exit(130)
            
            return choice in ("y", "yes")
        
        return False

    def _display_status_configuration(self) -> None:
        """Display explicit status policy before the first HTTP request."""
        if self.config.match_code_requested:
            self.logger.info(
                "Matching HTTP response status: "
                f"{self.config.match_code_expression}"
            )
        if self.config.filter_code_requested:
            self.logger.info(
                "Excluding HTTP response status: "
                f"{self.config.filter_code_expression}"
            )
        if self.config.match_code_requested or self.config.filter_code_requested:
            effective = self.config.match_codes - self.config.filter_codes
            self.logger.info(
                "Effective matching status: "
                f"{format_status_codes(effective)}"
            )
    
    def _perform_live_test(
        self,
        domain: str,
        all_domains: List[str],
        start_time: float,
    ) -> None:
        """Perform live testing on discovered subdomains."""
        tester = LiveTester(logger=self.logger)
        
        results = tester.test_domains(
            all_domains,
            workers=self.config.workers,
            stealth=self.config.stealth,
            stealth_min_delay=self.config.stealth_min_delay,
            stealth_max_delay=self.config.stealth_max_delay,
            http_version=self.config.http_version,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers=self.config.headers,
            proxies=self.network.proxies,
            bypass_tls=self.config.bypass_tls,
            force=self.config.force,
            match_codes=self.config.match_codes,
            filter_codes=self.config.filter_codes,
            no_color=self.config.no_color,
        )
        
        live_count = sum(1 for r in results if r.live)
        matched_count = sum(1 for r in results if r.status_matched)
        filtered_count = sum(1 for r in results if r.status_filtered)
        not_matched_count = sum(
            1 for r in results
            if r.http_response_received and not r.status_matched and not r.status_filtered
        )
        response_count = sum(1 for r in results if r.http_response_received)
        failed_count = sum(1 for r in results if not r.http_response_received)
        self.logger.info(f"[+] Live/matched subdomains: {live_count}/{len(all_domains)}")
        
        if self.config.threat_analysis:
            self.logger.info("[*] Running threat heuristics...")

            for result in results:
                threat_data = analyze_threat(result.domain)
                result.threat_score = threat_data["threat_score"]
                result.threat_level = threat_data["threat_level"]
                result.threat_indicators = threat_data["threat_indicators"]
            
            high = sum(1 for r in results if r.threat_level.value == "high")
            medium = sum(1 for r in results if r.threat_level.value == "medium")
            low = sum(1 for r in results if r.threat_level.value == "low")
            
            self.logger.info(
                f"[*] Threat summary: high={high}, medium={medium}, low={low}"
            )
            self.logger.warning(
                "[!] Threat scores are heuristics, not maliciousness verdicts."
            )
        
        all_path, live_path = save_live_test_output(
            all_domains=all_domains,
            results=results,
            output_dir=self.config.output_dir,
            domain=domain,
            filename=self.config.custom_filename,
            output_format=self.config.output_format,
        )
        
        self.logger.info(f"[+] ALL subdomains: {all_path}")
        self.logger.info(f"[+] LIVE subdomains: {live_path}")
        
        self._print_scan_summary(
            domain=domain,
            discovered=len(all_domains),
            tested=len(results),
            live=live_count,
            failed=failed_count,
            matched=matched_count,
            filtered=filtered_count,
            not_matched=not_matched_count,
            http_responses=response_count,
            network_failures=failed_count,
            duration=time.monotonic() - start_time,
            live_testing_performed=True,
        )
    
    def _save_discovery_results(
        self,
        domain: str,
        domains: List[str],
        start_time: float,
    ) -> None:
        """Save discovery-only results (no live testing)."""
        threat_results = None
        
        if self.config.threat_analysis:
            self.logger.info("[*] Running threat heuristics...")
            
            threat_results = []
            for d in domains:
                threat_data = analyze_threat(d)
                # analyze_threat returns a ThreatLevel *enum*. These discovery
                # dicts are serialized straight to JSON/XLSX and compared as
                # plain strings below (unlike the live path, which normalizes via
                # LiveTestResult.to_dict()). Convert to the enum value so the
                # summary counts are correct and json.dump never raises on the
                # non-serializable enum.
                threat_data["threat_level"] = threat_data["threat_level"].value
                result = {"domain": d}
                result.update(threat_data)
                threat_results.append(result)

            high = sum(1 for r in threat_results if r.get("threat_level") == "high")
            medium = sum(1 for r in threat_results if r.get("threat_level") == "medium")
            low = sum(1 for r in threat_results if r.get("threat_level") == "low")
            
            self.logger.info(
                f"[*] Threat summary: high={high}, medium={medium}, low={low}"
            )
        
        output_path = save_discovery_output(
            domains=domains,
            output_dir=self.config.output_dir,
            domain=domain,
            filename=self.config.custom_filename,
            output_format=self.config.output_format,
            threat_results=threat_results,
        )
        
        self.logger.info(f"[+] Subdomains saved: {output_path}")
        
        self._print_scan_summary(
            domain=domain,
            discovered=len(domains),
            tested=0,
            live=0,
            failed=0,
            matched=0,
            filtered=0,
            not_matched=0,
            http_responses=0,
            network_failures=0,
            duration=time.monotonic() - start_time,
            live_testing_performed=False,
        )
    
    def _print_scan_summary(
        self,
        domain: str,
        discovered: int,
        tested: int,
        live: int,
        failed: int,
        matched: int,
        filtered: int,
        not_matched: int,
        http_responses: int,
        network_failures: int,
        duration: float,
        live_testing_performed: bool,
    ) -> None:
        """Print final scan summary."""
        self.logger.info("")
        self.logger.info("=" * 50)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("=" * 50)
        self.logger.info(f"Target: {domain}")
        self.logger.info(f"Discovered: {discovered}")
        
        if live_testing_performed:
            self.logger.info(f"Tested: {tested}")
            self.logger.info(f"Live / Matched: {live} / {matched}")
            self.logger.info(f"Filtered: {filtered}")
            self.logger.info(f"Not Matched: {not_matched}")
            self.logger.info(f"Failed: {failed}")
            self.logger.info(f"HTTP Responses: {http_responses}")
            self.logger.info(f"Network Failures: {network_failures}")
        else:
            self.logger.info("Live testing: Not performed")
        
        self.logger.info(f"Duration: {duration:.1f}s")
        self.logger.info("=" * 50)
        self.logger.info("[+] Finished.")


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        validate_arguments(args, parser)
    except SystemExit:
        raise

    try:
        config = build_config(args)
    except ValueError as exc:
        parser.error(str(exc))

    logger = Logger(
        verbose=config.verbose,
        debug=config.debug,
        quiet=config.quiet,
        use_color=not config.no_color,
    )
    
    if config.bypass_tls:
        logger.warning("TLS certificate verification is disabled.")
    
    scanner = Scanner(config, logger)
    scanner.run()


if __name__ == "__main__":
    main()
