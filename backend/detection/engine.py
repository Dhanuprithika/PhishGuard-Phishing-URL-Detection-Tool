from datetime import datetime, timezone
from typing import Dict, Any
from .features import extract_url_features
from .ssl_cert import check_ssl_certificate
from .domain_intel import analyze_domain_intel
from .reputation import check_reputation
from .heuristics import evaluate_heuristics
from .ml_classifier import classifier
from ..models import ScanResponse, CheckItem, ThreatAnalysis
from ..agents.threat_analyst import threat_analyst_agent

EXPLANATIONS = {
    "safe": "This URL appears legitimate. The domain has a clean reputation, uses HTTPS, and shows no signs of phishing or deceptive behavior based on our multi-layered analysis.",
    "suspicious": "This URL exhibits characteristics commonly associated with phishing or unauthorized brand use. While not definitively malicious, caution is advised before interacting.",
    "phishing": "This URL exhibits multiple high-risk indicators consistent with active credential-harvesting phishing campaigns. Do not interact with this site or submit any information."
}

RECOMMENDATIONS = {
    "safe": "You can proceed, but always stay vigilant. Avoid entering sensitive credentials unless you trust the destination domain.",
    "suspicious": "Proceed with caution. Avoid entering passwords, credit card numbers, or sensitive data. Verify the site through official channels.",
    "phishing": "Do not visit this URL. If you received this link via email or message, report it as phishing. Do not enter any personal or financial information."
}

def analyze_url(raw_url: str) -> ScanResponse:
    """
    Main detection pipeline: runs feature extraction, SSL check, domain intel,
    reputation lookup, ML prediction, and heuristic rules to output an explainable ScanResponse.
    """
    # 1. Feature extraction
    features = extract_url_features(raw_url)
    normalized_url = features["normalized_url"]
    domain = features["domain"]
    hostname = features["hostname"]
    is_ip = features["is_ip"]

    # 2. SSL / TLS Inspection
    ssl_info = check_ssl_certificate(hostname, timeout=2.5)

    # 3. Domain Intelligence (DNS + WHOIS)
    domain_intel = analyze_domain_intel(domain, is_ip=is_ip, timeout=2.5)

    # 4. Reputation & Blacklist Lookup
    reputation = check_reputation(domain, normalized_url, is_ip=is_ip)

    # 5. ML Model Prediction
    ml_prob = classifier.predict_probability(features)

    # 6. Heuristic Evaluation
    heuristic_score, indicators, checks_data = evaluate_heuristics(
        features, domain_intel, ssl_info, reputation
    )

    # 7. Aggregate composite score (0-100)
    # ML contribution: up to 35 points if high probability
    ml_contribution = int(ml_prob * 35)
    raw_score = heuristic_score + ml_contribution

    if reputation.get("is_known_safe", False):
        final_score = min(raw_score, 8)
    else:
        final_score = max(0, min(99, raw_score))

    # 8. Determine Verdict
    if final_score >= 75 or reputation.get("blacklisted", False):
        verdict = "phishing"
    elif final_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Specific explanation customizations if high-risk brand impersonation
    if verdict == "phishing" and features.get("brand_impersonation"):
        explanation = f"High-risk credential harvesting detected mimicking {features['brand_impersonation'].capitalize()}."
    elif verdict == "suspicious" and features.get("brand_impersonation"):
        explanation = f"Potential brand impersonation of {features['brand_impersonation'].capitalize()}. Domain is not official."
    else:
        explanation = EXPLANATIONS[verdict]

    recommendation = RECOMMENDATIONS[verdict]

    checks = [
        CheckItem(
            label=c["label"],
            status=c["status"],
            detail=c["detail"]
        )
        for c in checks_data
    ]

    features_dict = {
        "entropy": features.get("entropy"),
        "url_length": features.get("url_length"),
        "num_subdomains": features.get("num_subdomains"),
        "is_ip": is_ip,
        "suspicious_keywords": features.get("suspicious_keywords_found", []),
        "ssl_issuer": ssl_info.get("issuer"),
        "ssl_valid": ssl_info.get("valid"),
        "dns_resolved": domain_intel.get("has_dns"),
        "ip_addresses": domain_intel.get("ip_addresses", []),
    }

    # Execute PhishGuard Threat Analyst Agent
    threat_analysis_obj = None
    try:
        raw_agent_analysis = threat_analyst_agent.analyze({
            "url": normalized_url,
            "verdict": verdict,
            "risk_score": final_score,
            "riskScore": final_score,
            "checks": checks_data,
            "indicators": indicators,
            "features": features_dict,
            "domain": domain or hostname,
            "https": features["has_https"] and ssl_info.get("valid", False),
            "blacklisted": reputation.get("blacklisted", False),
            "registration_age": domain_intel.get("registration_age", "Unknown"),
            "ml_confidence": round(ml_prob, 2),
            "explanation": explanation,
            "recommendation": recommendation,
        })
        if raw_agent_analysis:
            threat_analysis_obj = ThreatAnalysis(
                summary=raw_agent_analysis.get("summary", explanation),
                reasons=raw_agent_analysis.get("reasons", indicators[:3]),
                explanation=raw_agent_analysis.get("explanation", explanation),
                recommendation=raw_agent_analysis.get("recommendation", recommendation),
            )
    except Exception as agent_err:
        print(f"Threat analyst agent warning (gracefully recovered): {agent_err}")

    return ScanResponse(
        url=normalized_url,
        verdict=verdict,
        riskScore=final_score,
        checks=checks,
        indicators=indicators,
        explanation=explanation,
        recommendation=recommendation,
        domain=domain or hostname,
        https=features["has_https"] and ssl_info.get("valid", False),
        ipReputation=reputation.get("ip_reputation", "clean"),
        subdomains=features["num_subdomains"],
        blacklisted=reputation.get("blacklisted", False),
        registrationAge=domain_intel.get("registration_age", "Unknown"),
        scannedAt=datetime.now(timezone.utc),
        threatAnalysis=threat_analysis_obj,
        features=features_dict,
        ml_confidence=round(ml_prob, 2),
    )
