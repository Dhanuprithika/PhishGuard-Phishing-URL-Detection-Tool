import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional

def check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Safely inspects the TLS/SSL certificate of a host.
    Does not download payload data or follow HTTP redirects.
    """
    if not hostname:
        return {
            "has_https": False,
            "valid": False,
            "issuer": None,
            "subject": None,
            "days_until_expiration": None,
            "error": "No hostname provided"
        }

    # Clean hostname if it contains port
    clean_host = hostname.split(":")[0]

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {
                        "has_https": True,
                        "valid": False,
                        "issuer": "Unknown",
                        "subject": None,
                        "days_until_expiration": 0,
                        "error": "No certificate presented"
                    }

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"

                # Extract Subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                subject_name = subject_dict.get("commonName") or clean_host

                # Check Expiration
                not_after_str = cert.get("notAfter")
                days_left = None
                if not_after_str:
                    # e.g., 'May 10 12:00:00 2027 GMT'
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = max(0, (not_after - now).days)

                return {
                    "has_https": True,
                    "valid": True,
                    "issuer": issuer_name,
                    "subject": subject_name,
                    "days_until_expiration": days_left,
                    "error": None
                }

    except ssl.SSLCertVerificationError as e:
        return {
            "has_https": True,
            "valid": False,
            "issuer": "Untrusted / Self-signed",
            "subject": clean_host,
            "days_until_expiration": 0,
            "error": f"Invalid TLS certificate: {e.verify_message}"
        }
    except (socket.timeout, TimeoutError):
        return {
            "has_https": False,
            "valid": False,
            "issuer": None,
            "subject": None,
            "days_until_expiration": None,
            "error": "Connection timed out during TLS handshake"
        }
    except Exception as e:
        return {
            "has_https": False,
            "valid": False,
            "issuer": None,
            "subject": None,
            "days_until_expiration": None,
            "error": f"TLS error: {str(e)}"
        }
