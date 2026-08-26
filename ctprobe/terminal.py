"""Terminal capabilities and color output handling."""

import os
import sys
from importlib.util import find_spec
from typing import Optional


class TerminalCapabilities:
    """Detect terminal capabilities for output formatting."""
    
    def __init__(self):
        """Initialize terminal capabilities detection."""
        self._is_tty = sys.stdout.isatty()
        self._supports_color = self._detect_color_support()
        self._supports_rich = self._detect_rich()
    
    def _detect_color_support(self) -> bool:
        """
        Detect if terminal supports colors.
        
        Checks:
        - NO_COLOR environment variable
        - --no-color would have been passed (via environment)
        - Whether stdout is a TTY
        - TERM environment variable
        """
        # Check NO_COLOR env var (standard)
        if os.environ.get("NO_COLOR"):
            return False
        
        # Check FORCE_COLOR (some tools use this)
        if os.environ.get("FORCE_COLOR") == "1":
            return True
        
        # If not a TTY (piped/redirected), no color
        if not self._is_tty:
            return False
        
        # Check TERM
        term = os.environ.get("TERM", "").lower()
        if term == "dumb":
            return False
        
        return True
    
    def _detect_rich(self) -> bool:
        """Check if Rich library is available and can be used."""
        if not self._supports_color:
            return False
        
        return find_spec("rich") is not None
    
    @property
    def is_tty(self) -> bool:
        """Whether stdout is connected to a terminal."""
        return self._is_tty
    
    @property
    def supports_color(self) -> bool:
        """Whether terminal supports colored output."""
        return self._supports_color
    
    @property
    def supports_rich(self) -> bool:
        """Whether Rich library is available and should be used."""
        return self._supports_rich


def get_terminal_capabilities() -> TerminalCapabilities:
    """Get terminal capabilities singleton."""
    global _terminal_caps
    if "_terminal_caps" not in globals():
        _terminal_caps = TerminalCapabilities()
    return _terminal_caps


class ColorOutput:
    """
    ANSI color output helper.
    
    Only outputs colors if terminal supports it.
    Falls back to plain text otherwise.
    """
    
    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Foreground colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background colors (optional)
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    
    def __init__(self, enabled: Optional[bool] = None):
        """
        Initialize color output.
        
        Args:
            enabled: Explicitly enable/disable colors.
                    If None, auto-detect based on terminal.
        """
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = get_terminal_capabilities().supports_color
    
    def colorize(self, text: str, color: str) -> str:
        """Apply color to text if enabled."""
        if not self.enabled:
            return text
        return f"{color}{text}{self.RESET}"
    
    def success(self, text: str) -> str:
        """Green success text."""
        return self.colorize(text, self.GREEN)
    
    def error(self, text: str) -> str:
        """Red error text."""
        return self.colorize(text, self.RED)
    
    def warning(self, text: str) -> str:
        """Yellow warning text."""
        return self.colorize(text, self.YELLOW)
    
    def info(self, text: str) -> str:
        """Cyan info text."""
        return self.colorize(text, self.CYAN)
    
    def bold(self, text: str) -> str:
        """Bold text."""
        return self.colorize(text, self.BOLD)
    
    def dim(self, text: str) -> str:
        """Dim/gray text."""
        return self.colorize(text, self.DIM)
