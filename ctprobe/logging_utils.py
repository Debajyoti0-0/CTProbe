"""Logging and output utilities."""

import sys
from typing import Optional


class Logger:
    """Simple, clean logging with multiple verbosity levels."""

    def __init__(
        self,
        verbose: bool = False,
        debug: bool = False,
        quiet: bool = False,
        use_color: Optional[bool] = None,
    ):
        self.verbose = verbose
        self.debug = debug
        self.quiet = quiet
        self.color = None
        if use_color is False:
            return

        try:
            from .terminal import ColorOutput, get_terminal_capabilities
            caps = get_terminal_capabilities()
            enabled = caps.supports_color if use_color is None else use_color
            self.color = ColorOutput(enabled=enabled)
        except ImportError:
            self.color = None

    def info(self, message: str) -> None:
        """Log info message."""
        if not self.quiet:
            print(f"[+] {message}", file=sys.stdout)

    def warning(self, message: str) -> None:
        """Log warning message."""
        if not self.quiet:
            print(f"[!] {message}", file=sys.stdout)

    def error(self, message: str) -> None:
        """Log error message (always shown unless impossible)."""
        print(f"[-] {message}", file=sys.stderr)

    def verbose_msg(self, message: str) -> None:
        """Log verbose message."""
        if self.verbose and not self.quiet:
            print(f"[*] {message}", file=sys.stdout)

    def debug_msg(self, message: str) -> None:
        """Log debug message."""
        if self.debug and not self.quiet:
            print(f"[DEBUG] {message}", file=sys.stdout)

    def status(self, message: str, end: str = "\n") -> None:
        """Log status message with optional carriage return."""
        if not self.quiet:
            print(message, end=end, flush=True, file=sys.stdout)


def redact_credentials(value: str) -> str:
    """Redact credentials from strings like proxy URLs."""
    if not value:
        return value
    
    # Handle proxy URLs with credentials
    if "://" in value and "@" in value:
        scheme_part, rest = value.split("://", 1)
        if "@" in rest:
            creds, host_part = rest.rsplit("@", 1)
            # Redact the part before @
            if ":" in creds:
                username, _ = creds.split(":", 1)
                return f"{scheme_part}://{username}:***@{host_part}"
            else:
                return f"{scheme_part}://{creds}:***@{host_part}"
    
    return value
