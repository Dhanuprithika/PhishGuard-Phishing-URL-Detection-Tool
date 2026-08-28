import math
import re
import urllib.parse
from typing import Dict, Any, List, Optional

# High-risk TLDs commonly abused in automated phishing campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "buzz", "cam",
    "live", "loan", "fit", "rest", "icu", "sbs", "cfd", "shop", "quest", "monster",
    "surf", "pw", "cc", "ws", "country", "stream", "gdn", "kim", "download", "racing"
}

# Targeted brands for impersonation detection
TARGETED_BRANDS = [
    "paypal", "google", "apple", "microsoft", "netflix", "amazon", "facebook",
    "instagram", "dropbox", "coinbase", "binance", "chase", "wellsfargo",
    "bankofamerica", "meta", "twitter", "yahoo", "outlook", "office365", "steam",
    "discord", "adobe", "github", "stripe", "dhl", "fedex", "usps"
]

# Sensitive keywords frequently found in phishing paths & subdomains
PHISHING_KEYWORDS = [
    "login", "verify", "account", "secure", "security", "update", "bank",
    "password", "signin", "credential", "wallet", "confirm", "billing",
    "authenticate", "service", "portal", "webscr", "cmd", "session", "support",
    "recovery", "unlock", "validation", "submit", "oauth", "token", "authorize"
]

IP_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_PATTERN = re.compile(r"^\[?([a-fA-F0-9:]+)\]?$")

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """Extracts granular lexical, structural, and semantic features from a URL."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        # Fallback for malformed URLs
        return {
            "normalized_url": url,
            "url_length": len(url),
            "domain_length": 0,
            "hostname": "",
            "domain": "",
            "subdomain": "",
            "tld": "",
            "path": "",
            "query": "",
            "is_ip": False,
            "has_https": False,
            "has_port": False,
            "port": None,
            "num_dots": 0,
            "num_hyphens": 0,
            "num_at_symbols": 0,
            "num_subdomains": 0,
            "num_slashes": 0,
            "has_base64_or_hex": False,
            "entropy": calculate_entropy(url),
            "suspicious_keywords_found": [],
            "suspicious_tld": False,
            "brand_impersonation": None,
            "is_lookalike": False,
            "indicators": ["Malformed URL string"]
        }

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_path = path + ("?" + query if query else "")
    lower_url = url.lower()

    # IP Hostname Check
    is_ip = bool(IP_PATTERN.match(hostname)) or (":" in hostname and not hostname.startswith("["))

    # TLD and Domain extraction
    domain_parts = hostname.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    
    # Subdomain depth calculation
    if is_ip:
        subdomains_count = 0
        registered_domain = hostname
        subdomain_part = ""
    elif len(domain_parts) >= 2:
        # Simple effective domain extraction
        # handles common double tlds like .co.uk, .com.au if 3 parts
        if len(domain_parts) >= 3 and domain_parts[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
            registered_domain = ".".join(domain_parts[-3:])
            subdomain_part = ".".join(domain_parts[:-3])
            subdomains_count = len(domain_parts) - 3
        else:
            registered_domain = ".".join(domain_parts[-2:])
            subdomain_part = ".".join(domain_parts[:-2])
            subdomains_count = len(domain_parts) - 2
    else:
        registered_domain = hostname
        subdomain_part = ""
        subdomains_count = 0

    # Suspicious Keywords detection in domain, subdomain, and path
    keywords_found = []
    for kw in PHISHING_KEYWORDS:
        if kw in hostname or kw in full_path.lower():
            keywords_found.append(kw)

    # Obfuscation / Encoding patterns
    has_hex = bool(re.search(r"%[0-9a-fA-F]{2}", url))
    has_base64 = "base64" in lower_url or bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url))
    has_base64_or_hex = has_hex or has_base64

    # Brand Impersonation & Typosquatting
    brand_impersonation = None
    is_lookalike = False
    
    for brand in TARGETED_BRANDS:
        # Check if brand is in subdomain or path, but NOT the registered domain
        if brand in hostname and brand not in registered_domain.split(".")[0]:
            brand_impersonation = brand
            break
        # Check for brand typosquatting / character substitutions (e.g., paypa1, micros0ft, goog1e)
        typo_patterns = [
            brand.replace("l", "1"),
            brand.replace("o", "0"),
            brand.replace("i", "1"),
            brand.replace("e", "3"),
            brand.replace("a", "4"),
            brand.replace("m", "rn"),
            brand.replace("w", "vv"),
        ]
        for pattern in typo_patterns:
            if pattern != brand and pattern in hostname:
                brand_impersonation = brand
                is_lookalike = True
                break
        if brand_impersonation:
            break

    # Port checking
    has_port = parsed.port is not None
    port = parsed.port

    return {
        "normalized_url": url,
        "url_length": len(url),
        "domain_length": len(hostname),
        "hostname": hostname,
        "domain": registered_domain or hostname,
        "subdomain": subdomain_part,
        "tld": tld,
        "path": path,
        "query": query,
        "is_ip": is_ip,
        "has_https": parsed.scheme == "https",
        "has_port": has_port,
        "port": port,
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at_symbols": url.count("@"),
        "num_subdomains": max(0, subdomains_count),
        "num_slashes": path.count("/"),
        "has_base64_or_hex": has_base64_or_hex,
        "entropy": calculate_entropy(url),
        "domain_entropy": calculate_entropy(hostname),
        "suspicious_keywords_found": list(set(keywords_found)),
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "brand_impersonation": brand_impersonation,
        "is_lookalike": is_lookalike,
    }
