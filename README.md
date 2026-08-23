# Security Recon Toolkit (CLI)

A multi-threaded, defensive security reconnaissance and asset auditing CLI tool in Python 3.10+. Designed to assist AppSec engineers and penetration testers in conducting passive asset discovery, HTTP security header evaluations, and TLS/SSL certificate audits.

## Modules

1. **Subdomain Enumeration (`dns_enum.py`):** Passive DNS discovery and Certificate Transparency log inspection.
2. **HTTP Header Auditor (`header_audit.py`):** Scores target URLs against OWASP secure header recommendations (CSP, HSTS, X-Frame-Options).
3. **SSL/TLS Inspector (`ssl_checker.py`):** Analyzes SSL certificate validity, expiration dates, SANs, and cipher configurations.
4. **Port Banner Inspector (`port_inspector.py`):** Non-intrusive TCP socket inspection to identify running services.
5. **HTML Audit Reporter (`reporter.py`):** Generates executive and technical HTML vulnerability audit reports.

---

## Usage

```bash
# Audit security headers of a web endpoint
python3 -m recon_toolkit.cli audit-headers https://example.com --report report.html

# Check SSL/TLS certificate health
python3 -m recon_toolkit.cli check-ssl example.com

# Comprehensive Asset Scan
python3 -m recon_toolkit.cli full-audit example.com
```
