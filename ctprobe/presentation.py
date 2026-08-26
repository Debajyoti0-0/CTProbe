"""Rich-enhanced progress and result display."""

from typing import List, Optional
from .models import LiveTestResult
from .terminal import get_terminal_capabilities


class ProgressDisplay:
    """
    Progress display for live testing.
    
    Automatically uses Rich if available and terminal supports it,
    otherwise falls back to simple text display.
    """
    
    def __init__(
        self,
        total: int,
        show_progress: bool = True,
        use_rich: Optional[bool] = None,
    ):
        """
        Initialize progress display.
        
        Args:
            total: Total number of items to process
            show_progress: Whether to show progress at all
        """
        self.total = total
        self.show_progress = show_progress
        self.current = 0
        self.live_count = 0
        self.matched_count = 0
        self.filtered_count = 0
        self.failed_count = 0
        
        # Always initialized: _init_rich_progress() can flip _use_rich to
        # False when the Rich import fails at runtime, and the text fallback
        # path in update() depends on this attribute existing.
        self._last_printed_percent = -1

        detected_rich = get_terminal_capabilities().supports_rich
        self._use_rich = show_progress and (
            detected_rich if use_rich is None else use_rich
        )
        
        if self._use_rich:
            self._init_rich_progress()
    
    def _init_rich_progress(self) -> None:
        """Initialize Rich progress bar if available."""
        try:
            from rich.progress import Progress, BarColumn, TextColumn, DownloadColumn
            from rich.progress import TaskProgressColumn
            
            self.progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                DownloadColumn(),
            )
            self.task_id = self.progress.add_task(
                f"Testing subdomains: 0/{self.total}",
                total=self.total
            )
            self.progress.start()
        except ImportError:
            self._use_rich = False
    
    def update(
        self,
        live: bool = False,
        matched: bool = False,
        filtered: bool = False,
        failed: bool = False,
    ) -> None:
        """
        Update progress after testing one domain.
        
        Args:
            live: Whether the domain was live
            failed: Whether testing failed
        """
        self.current += 1
        if live:
            self.live_count += 1
        if matched:
            self.matched_count += 1
        if filtered:
            self.filtered_count += 1
        if failed:
            self.failed_count += 1
        
        if not self.show_progress:
            return
        
        if self._use_rich:
            try:
                description = (
                    f"Testing subdomains: {self.current}/{self.total} | "
                    f"Live: {self.live_count} | Matched: {self.matched_count} | "
                    f"Filtered: {self.filtered_count} | Failed: {self.failed_count}"
                )
                self.progress.update(
                    self.task_id,
                    description=description,
                    advance=1
                )
            except Exception:
                # If Rich fails, silently continue
                pass
        else:
            # Simple text-based progress (non-spamming)
            percent = int(100 * self.current / self.total)
            if percent % 10 == 0 and percent != self._last_printed_percent:
                print(
                    f"Testing subdomains: {self.current}/{self.total} | "
                    f"Live: {self.live_count} | Matched: {self.matched_count} | "
                    f"Filtered: {self.filtered_count} | Failed: {self.failed_count}"
                )
                self._last_printed_percent = percent
    
    def stop(self) -> None:
        """Stop progress display."""
        if self._use_rich and hasattr(self, 'progress'):
            try:
                self.progress.stop()
            except Exception:
                pass


class ResultsDisplay:
    """Display formatted scan results."""
    
    def __init__(self, use_rich: Optional[bool] = None):
        """
        Initialize results display.
        
        Args:
            use_rich: Force enable/disable Rich.
                     If None, auto-detect.
        """
        if use_rich is None:
            self._use_rich = get_terminal_capabilities().supports_rich
        else:
            self._use_rich = use_rich and get_terminal_capabilities().supports_rich
    
    def display_live_results_table(self, results: List[LiveTestResult]) -> None:
        """
        Display live testing results in table format.
        
        Uses Rich table if available, otherwise simple text.
        """
        if not results:
            return
        
        live_results = [r for r in results if r.live]
        
        if not live_results:
            print("\nNo live subdomains found.")
            return
        
        if self._use_rich:
            self._display_rich_table(live_results)
        else:
            self._display_text_table(live_results)
    
    def _display_rich_table(self, results: List[LiveTestResult]) -> None:
        """Display results using Rich table."""
        try:
            from rich.markup import escape
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Live Subdomains")

            table.add_column("Subdomain", style="cyan", no_wrap=True)
            table.add_column("Status Code", justify="right")
            table.add_column("HTTP Version")
            table.add_column("Response Time (ms)", justify="right")
            
            for result in results:
                table.add_row(
                    escape(result.domain),
                    escape(str(result.status_code)),
                    escape(result.http_version or "unknown"),
                    escape(str(result.response_time_ms or "N/A")),
                )
            
            console.print(table)
        except Exception:
            # Fallback to text if Rich fails
            self._display_text_table(results)
    
    def _display_text_table(self, results: List[LiveTestResult]) -> None:
        """Display results as plain text."""
        print("\n" + "="*80)
        print(f"{'Subdomain':<40} {'Status':<8} {'HTTP':<8} {'Time (ms)':<10}")
        print("-"*80)
        
        for result in results:
            domain = result.domain[:40]
            status = str(result.status_code)
            http_version = result.http_version or "unknown"
            response_time = str(result.response_time_ms or "N/A")
            
            print(f"{domain:<40} {status:<8} {http_version:<8} {response_time:<10}")
        
        print("="*80)
    
    def display_summary(
        self,
        target: str,
        discovered_count: int,
        tested_count: int,
        live_count: int,
        failed_count: int,
        duration_seconds: float,
    ) -> None:
        """
        Display scan summary.
        
        Args:
            target: Target domain
            discovered_count: Number of subdomains discovered
            tested_count: Number of subdomains tested
            live_count: Number of live subdomains
            failed_count: Number of failed tests
            duration_seconds: Total scan duration
        """
        if self._use_rich:
            self._display_rich_summary(
                target, discovered_count, tested_count,
                live_count, failed_count, duration_seconds
            )
        else:
            self._display_text_summary(
                target, discovered_count, tested_count,
                live_count, failed_count, duration_seconds
            )
    
    def _display_rich_summary(
        self,
        target: str,
        discovered_count: int,
        tested_count: int,
        live_count: int,
        failed_count: int,
        duration_seconds: float,
    ) -> None:
        """Display summary using Rich."""
        try:
            from rich.markup import escape
            from rich.panel import Panel
            from rich.console import Console
            
            console = Console()
            
            summary_text = (
                f"Target: {escape(target)}\n"
                f"Discovered: {discovered_count}\n"
                f"Tested: {tested_count}\n"
                f"Live: {live_count}\n"
                f"Failed: {failed_count}\n"
                f"Duration: {duration_seconds:.2f}s"
            )
            
            console.print(
                Panel(summary_text, title="Scan Summary", border_style="blue")
            )
        except Exception:
            self._display_text_summary(
                target, discovered_count, tested_count,
                live_count, failed_count, duration_seconds
            )
    
    def _display_text_summary(
        self,
        target: str,
        discovered_count: int,
        tested_count: int,
        live_count: int,
        failed_count: int,
        duration_seconds: float,
    ) -> None:
        """Display summary as plain text."""
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        print(f"Target:     {target}")
        print(f"Discovered: {discovered_count}")
        print(f"Tested:     {tested_count}")
        print(f"Live:       {live_count}")
        print(f"Failed:     {failed_count}")
        print(f"Duration:   {duration_seconds:.2f}s")
        print("="*80)
