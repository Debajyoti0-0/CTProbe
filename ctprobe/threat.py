"""Threat analysis heuristics."""

import re
from .models import ThreatLevel


# Suspicious TLDs that are commonly abused
SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "download", "top", "work", "country",
    "gq", "tk", "ml", "ga", "cf", "xyz", "pw", "online", "site",
    "website", "space", "tech", "trade", "science", "date",
}

# Suspicious keywords commonly found in phishing domains
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "signin", "password", "wallet", "payment", "invoice", "confirm",
    "validate", "authenticate", "activate", "reset", "urgent",
}


def analyze_threat(domain: str) -> dict:
    """
    Run basic threat heuristics on a domain.
    
    Returns dict with:
    - threat_score: int (0-N)
    - threat_level: ThreatLevel
    - threat_indicators: list of strings
    """
    indicators = []
    score = 0
    
    # Check TLD
    parts = domain.split(".")
    if len(parts) >= 2:
        tld = parts[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            indicators.append(f"suspicious_tld:{tld}")
            score += 2
    
    # Check length (very long domains may indicate random generation)
    if len(domain) > 50:
        indicators.append("very_long_domain")
        score += 1
    
    # Check for excessive hyphens (common in phishing)
    if domain.count("-") >= 3:
        indicators.append("many_hyphens")
        score += 1
    
    # Check for many consecutive digits
    if re.search(r"\d{4,}", domain):
        indicators.append("many_consecutive_digits")
        score += 1
    
    # Check for suspicious keywords
    domain_lower = domain.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain_lower:
            indicators.append(f"keyword:{keyword}")
            score += 1
    
    # Check subdomain depth (very deep subdomains may be suspicious)
    if domain.count(".") >= 4:
        indicators.append("excessive_subdomain_depth")
        score += 1
    
    # Determine threat level
    if score >= 5:
        level = ThreatLevel.HIGH
    elif score >= 3:
        level = ThreatLevel.MEDIUM
    elif score >= 1:
        level = ThreatLevel.LOW
    else:
        level = ThreatLevel.NONE
    
    return {
        "threat_score": score,
        "threat_level": level,
        "threat_indicators": indicators,
    }


def apply_threat_analysis(results: list) -> None:
    """
    Apply threat analysis to a list of results in-place.
    
    Modifies LiveTestResult or dict objects to add threat fields.
    """
    for result in results:
        threat_data = analyze_threat(result["domain"] if isinstance(result, dict) else result.domain)
        
        if isinstance(result, dict):
            result.update(threat_data)
        else:
            # LiveTestResult object
            result.threat_score = threat_data["threat_score"]
            result.threat_level = threat_data["threat_level"]
            result.threat_indicators = threat_data["threat_indicators"]
