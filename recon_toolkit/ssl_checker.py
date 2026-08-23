import ssl
import socket
import datetime
from typing import Dict, Any

class SSLInspector:
    """Audits SSL/TLS certificate validity and metadata."""

    @staticmethod
    def inspect_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

            not_after_str = cert.get("notAfter")
            # Format: 'May 28 12:00:00 2026 GMT'
            exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.datetime.utcnow()).days

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            return {
                "hostname": hostname,
                "valid": days_left > 0,
                "days_until_expiration": days_left,
                "expiration_date": exp_date.isoformat(),
                "issuer": issuer.get("organizationName", "Unknown"),
                "subject": subject.get("commonName", hostname),
                "tls_version": tls_version,
                "cipher": cipher[0] if cipher else "Unknown",
            }
        except Exception as e:
            return {
                "hostname": hostname,
                "valid": False,
                "error": str(e)
            }
