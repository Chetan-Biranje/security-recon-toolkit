import sys
import json
import argparse
from .header_audit import SecurityHeaderAuditor
from .ssl_checker import SSLInspector
from .reporter import HTMLReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Security Recon Toolkit CLI - Chetan Biranje")
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")

    # Command: audit-headers
    audit_parser = subparsers.add_parser("audit-headers", help="Audit HTTP security headers")
    audit_parser.add_argument("url", help="Target URL (e.g. example.com or https://example.com)")
    audit_parser.add_argument("--report", help="Save HTML report to path", default=None)

    # Command: check-ssl
    ssl_parser = subparsers.add_parser("check-ssl", help="Inspect SSL/TLS certificate")
    ssl_parser.add_argument("hostname", help="Target domain name")

    args = parser.parse_args()

    if args.command == "audit-headers":
        result = SecurityHeaderAuditor.audit_url(args.url)
        print(json.dumps(result, indent=2))
        if args.report:
            html = HTMLReportGenerator.generate(result)
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"Report successfully saved to {args.report}")

    elif args.command == "check-ssl":
        result = SSLInspector.inspect_certificate(args.hostname)
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
