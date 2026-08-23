import urllib.request
import ssl
from typing import Dict, Any, List

class SecurityHeaderAuditor:
    """Audits HTTP responses for standard OWASP security headers."""

    RECOMMENDED_HEADERS = {
        "Strict-Transport-Security": {"weight": 20, "desc": "Enforces HTTPS connections."},
        "Content-Security-Policy": {"weight": 25, "desc": "Mitigates XSS and data injection attacks."},
        "X-Frame-Options": {"weight": 15, "desc": "Protects against Clickjacking."},
        "X-Content-Type-Options": {"weight": 10, "desc": "Prevents MIME-sniffing vulnerabilities."},
        "Referrer-Policy": {"weight": 10, "desc": "Controls referrer information leakage."},
        "Permissions-Policy": {"weight": 10, "desc": "Restricts browser feature usage."},
        "Cache-Control": {"weight": 10, "desc": "Prevents caching of sensitive data."},
    }

    @classmethod
    def audit_url(cls, url: str) -> Dict[str, Any]:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SecurityReconToolkit/1.0 (Audit Engine)"}
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                headers = dict(response.headers)
                status_code = response.status
        except Exception as e:
            return {"error": f"Failed to connect: {str(e)}", "target": url}

        score = 0
        present = {}
        missing = {}

        for header_name, meta in cls.RECOMMENDED_HEADERS.items():
            # Case-insensitive header match
            matching_key = next((k for k in headers if k.lower() == header_name.lower()), None)
            if matching_key:
                score += meta["weight"]
                present[header_name] = headers[matching_key]
            else:
                missing[header_name] = meta["desc"]

        # Calculate Grade
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        else:
            grade = "F"

        return {
            "target": url,
            "status_code": status_code,
            "score": score,
            "grade": grade,
            "present_headers": present,
            "missing_headers": missing,
        }
