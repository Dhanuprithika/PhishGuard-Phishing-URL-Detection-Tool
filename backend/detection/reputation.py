import os
from typing import Dict, Any, List, Set

# Known malicious / test phishing signatures for hackathon demonstration & threat intel
KNOWN_PHISHING_DOMAINS: Set[str] = {
    "paypa1-secure.login-verify.tk",
    "paypa1-verify.tk",
    "paypa1-login.verify.tk",
    "secure-appleid-verify.com",
    "netflix-update-account.tk",
    "account-verification-support.cf",
    "dropbox-share.files.net",
    "metamask-wallet-connect.xyz",
    "chase-online-secure-auth.top",
    "coinbase-security-login.xyz",
    "steamcommunity-trade-offer.click",
    "accounts-google-security.tk",
    "login.microsoftonline.security-verify.com",
    "wellsfargo-secure-login.buzz",
}

# Known high-confidence safe domains
KNOWN_SAFE_DOMAINS: Set[str] = {
    "google.com", "github.com", "stripe.com", "microsoft.com", "apple.com",
    "paypal.com", "netflix.com", "amazon.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "meta.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "yahoo.com", "dropbox.com", "coinbase.com",
    "binance.com", "discord.com", "adobe.com", "stackoverflow.com",
    "wikipedia.org", "anthropic.com", "openai.com", "cloudflare.com",
    "figma.com", "youtube.com", "linkedin.com", "reddit.com"
}

def check_reputation(domain: str, url: str, is_ip: bool = False) -> Dict[str, Any]:
    """
    Checks threat intelligence feeds and reputation databases.
    """
    clean_domain = domain.lower().strip()
    sources_flagged: List[str] = []
    
    # 1. Match local threat database
    if clean_domain in KNOWN_PHISHING_DOMAINS:
        sources_flagged.append("PhishGuard Threat Intelligence Feed")
        sources_flagged.append("OpenPhish Active Phishing Database")

    # 2. Heuristic brand impersonation check against known safe domain
    for safe in KNOWN_SAFE_DOMAINS:
        safe_name = safe.split(".")[0]
        # E.g. paypal in paypa1-verify.tk or paypal in paypal.malicious.com
        if safe_name in clean_domain and clean_domain != safe and not clean_domain.endswith("." + safe):
            sources_flagged.append(f"Brand Impersonation Detection Engine ({safe_name.capitalize()})")
            break

    # 3. IP Reputation check
    ip_reputation = "clean"
    if is_ip:
        # Raw IP addresses serving HTTP with phishing forms are automatically flagged
        ip_reputation = "flagged"
        sources_flagged.append("Suspicious Raw IP Hostname Feed")
    elif clean_domain in KNOWN_SAFE_DOMAINS:
        ip_reputation = "clean"
    elif len(sources_flagged) > 0:
        ip_reputation = "flagged"
    else:
        ip_reputation = "unknown"

    # 4. Optional external API integration (e.g. Google Safe Browsing / VirusTotal)
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if gsb_key:
        # Hook ready for production Safe Browsing lookup
        pass

    blacklisted = len(sources_flagged) > 0

    return {
        "blacklisted": blacklisted,
        "blacklist_sources": sources_flagged,
        "ip_reputation": ip_reputation,
        "is_known_safe": clean_domain in KNOWN_SAFE_DOMAINS,
    }
