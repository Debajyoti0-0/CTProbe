"""Environment and system checks."""

import ssl
import sys
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .logging_utils import Logger


@dataclass(frozen=True)
class EnvironmentInfo:
    """Read-only runtime and terminal capability information."""
    os_name: str
    os_release: str
    architecture: str
    python_version: str
    python_implementation: str
    executable: str
    tls_backend: str
    virtual_environment: bool
    container: bool
    wsl: bool
    tty: bool
    encoding: str


def detect_environment() -> EnvironmentInfo:
    """Collect portable environment facts without changing process state."""
    version_text = platform.python_version()
    implementation = platform.python_implementation()
    container = False
    if os.name != "nt":
        container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    container = container or bool(os.environ.get("container"))
    wsl = "microsoft" in platform.release().lower() or "microsoft" in platform.version().lower()
    return EnvironmentInfo(
        os_name=platform.system(),
        os_release=platform.release(),
        architecture=platform.machine() or platform.architecture()[0],
        python_version=version_text,
        python_implementation=implementation,
        executable=sys.executable,
        tls_backend=ssl.OPENSSL_VERSION,
        virtual_environment=(sys.prefix != sys.base_prefix or "CONDA_PREFIX" in os.environ),
        container=container,
        wsl=wsl,
        tty=sys.stdout.isatty(),
        encoding=sys.stdout.encoding or "unknown",
    )


def check_ssl_environment(logger: Optional[Logger] = None) -> None:
    """Report the Python runtime TLS backend without blocking the scan."""
    logger = logger or Logger()
    
    try:
        environment = detect_environment()
        backend_version = ssl.OPENSSL_VERSION
        logger.debug_msg(
            f"OS: {environment.os_name} {environment.os_release}; "
            f"Architecture: {environment.architecture}"
        )
        logger.debug_msg(
            f"Python: {environment.python_implementation} {environment.python_version}"
        )
        logger.debug_msg(f"Executable: {environment.executable}")
        logger.debug_msg(f"Virtual environment: {'yes' if environment.virtual_environment else 'no'}")
        logger.debug_msg(f"Container: {'yes' if environment.container else 'no'}")
        logger.debug_msg(f"WSL: {'yes' if environment.wsl else 'no'}")
        logger.debug_msg(f"TTY: {'yes' if environment.tty else 'no'}")
        logger.debug_msg(f"Encoding: {environment.encoding}")
        logger.debug_msg(f"ssl.OPENSSL_VERSION: {backend_version}")
        logger.debug_msg(f"ssl.OPENSSL_VERSION_INFO: {ssl.OPENSSL_VERSION_INFO}")

        if "libressl" in backend_version.lower():
            logger.warning(f"TLS backend: {backend_version}")
            logger.warning(
                "urllib3 v2 officially supports OpenSSL 1.1.1+."
            )
            logger.warning(
                "Your Python ssl module is using LibreSSL."
            )
            logger.warning(
                "Consider using a Python build linked against OpenSSL 1.1.1+ "
                "or OpenSSL 3.x."
            )
            logger.info("Continuing with the current Python TLS environment.")
        elif "openssl" in backend_version.lower():
            logger.info(f"TLS backend: {backend_version}")
    
    except Exception as exc:
        logger.debug_msg(f"Could not detect OpenSSL version: {exc}")
