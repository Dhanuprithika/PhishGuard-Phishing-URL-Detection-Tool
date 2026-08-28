import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import dns.resolver

try:
    import whois
except ImportError:
    whois = None

def get_domain_age_string(creation_date: Optional[datetime]) -> str:
    """Formats creation date into a human readable age string."""
    if not creation_date:
        return "Unknown"

    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if not isinstance(creation_date, datetime):
        return "Unknown"

    # Normalize timezone
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    total_days = max(0, (now - creation_date).days)
    years = total_days // 365
    months = (total_days % 365) // 30
    days = total_days % 30

    if years > 0:
        return f"{years} year{'s' if years != 1 else ''}{f', {months} month' + ('s' if months != 1 else '') if months > 0 else ''}"
    if months > 0:
        return f"{months} month{'s' if months != 1 else ''}, {days} day{'s' if days != 1 else ''}"
    return f"{total_days} day{'s' if total_days != 1 else ''}"

def analyze_domain_intel(domain: str, is_ip: bool = False, timeout: float = 3.0) -> Dict[str, Any]:
    """Safely retrieves DNS and WHOIS domain intelligence."""
    if is_ip or not domain:
        return {
            "domain": domain,
            "ip_addresses": [domain] if is_ip else [],
            "has_dns": True if is_ip else False,
            "has_mx_records": False,
            "registration_age": "N/A (Direct IP)" if is_ip else "Unknown",
            "is_newly_registered": False,
            "registrar": "N/A",
            "country": "Unknown",
        }

    ip_addresses: List[str] = []
    has_dns = False
    has_mx = False

    # 1. DNS Resolution
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout

        try:
            answers = resolver.resolve(domain, "A")
            ip_addresses = [r.to_text() for r in answers]
            has_dns = len(ip_addresses) > 0
        except Exception:
            # Fallback to standard socket
            try:
                ip_addresses = [socket.gethostbyname(domain)]
                has_dns = True
            except Exception:
                has_dns = False

        # Check MX Records
        try:
            mx_answers = resolver.resolve(domain, "MX")
            has_mx = len(mx_answers) > 0
        except Exception:
            has_mx = False

    except Exception:
        has_dns = False

    # 2. WHOIS Information
    registration_age = "Unknown"
    is_newly_registered = False
    registrar = "Unknown"
    country = "Unknown"

    if whois is not None and has_dns:
        try:
            w = whois.whois(domain)
            if w:
                c_date = w.creation_date
                if c_date:
                    if isinstance(c_date, list):
                        c_date = c_date[0]
                    registration_age = get_domain_age_string(c_date)
                    if isinstance(c_date, datetime):
                        if c_date.tzinfo is None:
                            c_date = c_date.replace(tzinfo=timezone.utc)
                        days_old = (datetime.now(timezone.utc) - c_date).days
                        is_newly_registered = days_old < 30

                registrar = str(w.registrar or "Unknown")
                country = str(w.country or "Unknown")
        except Exception:
            # WHOIS lookup failed, keep default graceful responses
            pass

    return {
        "domain": domain,
        "ip_addresses": ip_addresses,
        "has_dns": has_dns,
        "has_mx_records": has_mx,
        "registration_age": registration_age,
        "is_newly_registered": is_newly_registered,
        "registrar": registrar,
        "country": country,
    }
