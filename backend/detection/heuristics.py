from typing import Dict, Any, List, Tuple

def evaluate_heuristics(
    features: Dict[str, Any],
    domain_intel: Dict[str, Any],
    ssl_info: Dict[str, Any],
    reputation: Dict[str, Any],
) -> Tuple[int, List[str], List[Dict[str, Any]]]:
    """
    Evaluates rule-based heuristic risk signals.
    Returns:
        (risk_score_delta, indicators, check_items)
    """
    score = 0
    indicators: List[str] = []

    # 1. Protocol / HTTPS
    if not features["has_https"]:
        score += 18
        indicators.append("No HTTPS encryption")
        check_https = {
            "label": "HTTPS / Certificate",
            "status": "fail",
            "detail": "Connection is unencrypted (HTTP only)"
        }
    elif not ssl_info.get("valid", True):
        score += 25
        indicators.append("Invalid or untrusted TLS certificate")
        check_https = {
            "label": "HTTPS / Certificate",
            "status": "fail",
            "detail": ssl_info.get("error", "Untrusted TLS certificate")
        }
    else:
        check_https = {
            "label": "HTTPS / Certificate",
            "status": "pass",
            "detail": f"Valid TLS certificate ({ssl_info.get('issuer', 'Standard CA')})"
        }

    # 2. IP Hostname
    if features["is_ip"]:
        score += 35
        indicators.append("IP address used as hostname")

    # 3. Brand Impersonation & Typosquatting
    if features.get("brand_impersonation"):
        brand = features["brand_impersonation"]
        if features.get("is_lookalike"):
            score += 35
            indicators.append(f"Lookalike domain mimicking {brand.capitalize()}")
        else:
            score += 25
            indicators.append(f"Brand impersonation targeting {brand.capitalize()}")

    # 4. Suspicious TLD
    if features["suspicious_tld"]:
        score += 20
        indicators.append(f"High-risk top-level domain (.{features['tld']})")

    # 5. Phishing Keywords
    kws = features.get("suspicious_keywords_found", [])
    if len(kws) >= 3:
        score += 28
        indicators.append(f"Multiple credential keywords ({', '.join(kws[:3])})")
    elif len(kws) >= 1:
        score += 15
        indicators.append(f"Suspicious keyword in URL ('{kws[0]}')")

    # 6. Deep Subdomains
    sub_count = features["num_subdomains"]
    if sub_count >= 3:
        score += 20
        indicators.append("Excessive subdomain depth")
    elif sub_count == 2:
        score += 8

    # 7. Obfuscation / Encoding
    if features["has_base64_or_hex"]:
        score += 18
        indicators.append("Encoded/obfuscated URL components")

    # 8. High Entropy
    if features["entropy"] > 4.8:
        score += 12
        indicators.append("Unusually high URL randomness/entropy")

    # 9. Abnormal Port
    if features.get("has_port") and features.get("port") not in [80, 443, None]:
        score += 15
        indicators.append(f"Non-standard web port ({features['port']})")

    # 10. Domain Registration Age
    reg_age = domain_intel.get("registration_age", "Unknown")
    is_new = domain_intel.get("is_newly_registered", False)
    if is_new:
        score += 20
        indicators.append("Domain registered recently (< 30 days)")
        check_domain = {
            "label": "Domain Age & Registration",
            "status": "warn",
            "detail": f"Recently registered: {reg_age}"
        }
    elif reg_age != "Unknown" and not features["is_ip"]:
        check_domain = {
            "label": "Domain Age & Registration",
            "status": "pass",
            "detail": f"Established domain: {reg_age}"
        }
    else:
        check_domain = {
            "label": "Domain Age & Registration",
            "status": "warn" if features["is_ip"] else "pass",
            "detail": reg_age if features["is_ip"] else "Domain active and reachable"
        }

    # 11. Reputation / Blacklist
    if reputation.get("blacklisted", False):
        score += 40
        indicators.append("Matches known threat signatures on blacklists")
        check_reputation = {
            "label": "Reputation & Blacklists",
            "status": "fail",
            "detail": f"Flagged: {', '.join(reputation.get('blacklist_sources', ['Threat Feed'])[:2])}"
        }
    elif reputation.get("is_known_safe", False):
        score = max(2, min(score, 10))  # cap known safe domains at very low score
        check_reputation = {
            "label": "Reputation & Blacklists",
            "status": "pass",
            "detail": "Verified reputable domain"
        }
    else:
        check_reputation = {
            "label": "Reputation & Blacklists",
            "status": "pass",
            "detail": "No blacklist entries found"
        }

    # 12. URL Structure Check Item
    if features["is_ip"] or features["has_base64_or_hex"]:
        check_structure = {
            "label": "URL Structure",
            "status": "fail",
            "detail": "IP hostname or obfuscated components detected"
        }
    elif sub_count >= 3 or features["num_hyphens"] > 3:
        check_structure = {
            "label": "URL Structure",
            "status": "warn",
            "detail": "Unusually deep subdomain or deceptive hyphenation"
        }
    else:
        check_structure = {
            "label": "URL Structure",
            "status": "pass",
            "detail": "URL structure looks normal"
        }

    # 13. Threat Indicators Summary Item
    check_threats = {
        "label": "Threat Indicators",
        "status": "pass" if len(indicators) == 0 else "warn" if len(indicators) <= 2 else "fail",
        "detail": f"{len(indicators)} indicator{'s' if len(indicators) != 1 else ''} detected"
    }

    checks = [
        check_structure,
        check_domain,
        check_https,
        check_reputation,
        check_threats
    ]

    return score, indicators, checks
