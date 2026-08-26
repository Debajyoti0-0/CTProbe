"""Domain normalization and validation."""

import re
from importlib import import_module
from urllib.parse import urlparse
from typing import List, Optional, Set


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name.
    
    - Lowercase
    - Remove leading/trailing whitespace
    - Remove trailing dot
    - Remove schemes if accidentally included
    - Remove paths if accidentally included
    - Remove ports
    - Extract hostname from full URL if needed
    
    Returns empty string if invalid.
    """
    if not domain:
        return ""
    
    domain = domain.strip()
    
    if not domain:
        return ""
    
    # Try to parse as URL if it looks like one
    if "://" in domain or ":" in domain or "/" in domain:
        try:
            # Add scheme if missing
            if "://" not in domain:
                domain = f"http://{domain}"
            
            parsed = urlparse(domain)
            hostname = parsed.hostname
            
            if hostname:
                domain = hostname
            else:
                return ""
        except Exception:
            return ""
    
    domain = domain.lower().rstrip(".")
    
    # Validate basic domain structure
    if not domain or not is_valid_domain(domain):
        return ""
    
    return domain


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Basic validation:
    - Contains at least one dot (with exceptions for localhost)
    - Only alphanumeric, dots, and hyphens
    - Does not start or end with hyphen
    - Each label is 1-63 chars
    - Total length <= 253 chars
    """
    if not domain or len(domain) > 253:
        return False
    
    labels = domain.split(".")
    
    if len(labels) < 2 and domain != "localhost":
        return False
    
    for label in labels:
        # Label length
        if not label or len(label) > 63:
            return False
        
        # Start/end with hyphen
        if label.startswith("-") or label.endswith("-"):
            return False
        
        # Valid characters
        if not re.match(r"^[a-zA-Z0-9-]+$", label):
            return False
    
    return True


def extract_domain_names_from_text(text: Optional[str]) -> Set[str]:
    """
    Extract certificate DNS names from text (e.g., a CT log response).

    Uses a regex pattern to find domain-like strings and validates them.
    Returned names are raw certificate identities and are not guaranteed to
    be subdomains of any particular target — filter with is_subdomain_of().
    """
    if not text:
        return set()
    
    pattern = re.compile(
        r"\b"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}"
        r"\b",
        re.IGNORECASE
    )
    
    domains = set()
    
    for match in pattern.finditer(text):
        domain_str = match.group(0).lower().rstrip(".")
        
        # Validate before adding
        if is_valid_domain(domain_str):
            domains.add(domain_str)
    
    return domains


def deduplicate_domains(domains: List[str]) -> List[str]:
    """
    Deduplicate domains case-insensitively and return sorted list.
    """
    unique = set()
    for domain in domains:
        normalized = normalize_domain(domain)
        if normalized:
            unique.add(normalized)
    
    return sorted(unique)


def normalize_wildcard(domain: str) -> str:
    """
    Normalize wildcard certificate names.
    
    *.example.com -> example.com (remove wildcard for parent domain testing)
    """
    if domain.startswith("*."):
        return domain[2:]
    return domain


def is_subdomain_of(hostname: str, target: str) -> bool:
    """
    Label-aware check that ``hostname`` belongs to the ``target`` domain.

    Uses label-boundary matching, never bare suffix comparison, so
    ``evil-example.com`` does NOT match ``example.com``.

    The apex itself counts as a member (CT logs legitimately contain it).
    Wildcard names must be normalized (via normalize_wildcard) beforehand.
    """
    hostname = normalize_domain(hostname)
    target = normalize_domain(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def get_registrable_domain(domain: str) -> str:
    """Return the public-suffix-aware registrable domain for a hostname."""
    normalized = normalize_domain(domain)
    if not normalized:
        return ""

    try:
        tldextract = import_module("tldextract")
        extracted = tldextract.extract(normalized)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return normalized
    except ImportError:
        # Keep common multi-label suffixes correct when the optional dependency
        # is unavailable; installation is recommended for complete PSL data.
        labels = normalized.split(".")
        multi_label_suffixes = {
            "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "com.br",
            "co.in", "co.jp", "co.nz", "com.cn", "com.mx",
        }
        suffix_length = 2 if ".".join(labels[-2:]) in multi_label_suffixes else 1
        if len(labels) <= suffix_length:
            return normalized
        return ".".join(labels[-(suffix_length + 1):])
