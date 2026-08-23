import json
from typing import Dict, Any

class HTMLReportGenerator:
    """Generates structured HTML security audit reports."""

    @staticmethod
    def generate(audit_data: Dict[str, Any]) -> str:
        target = audit_data.get("target", "Target Host")
        score = audit_data.get("score", 0)
        grade = audit_data.get("grade", "N/A")
        present = audit_data.get("present_headers", {})
        missing = audit_data.get("missing_headers", {})

        present_rows = "".join(f"<tr><td><code>{k}</code></td><td>{v}</td></tr>" for k, v in present.items())
        missing_rows = "".join(f"<tr class='bad'><td><code>{k}</code></td><td>{v}</td></tr>" for k, v in missing.items())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 24px; max-width: 900px; margin: 0 auto; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
        h1, h2 {{ color: #38bdf8; }}
        .badge {{ display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; font-size: 20px; }}
        .badge-A {{ background: #22c55e; color: #000; }}
        .badge-B {{ background: #eab308; color: #000; }}
        .badge-C, .badge-F {{ background: #ef4444; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        tr.bad {{ background: rgba(239, 68, 68, 0.1); color: #fca5a5; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ Security Recon Toolkit - Audit Report</h1>
        <p>Target: <strong>{target}</strong></p>
        <p>Security Posture Score: <strong>{score}/100</strong> | Grade: <span class="badge badge-{grade}">{grade}</span></p>

        <h2>✅ Implemented Security Headers</h2>
        <table>
            <thead><tr><th>Header Name</th><th>Configured Value</th></tr></thead>
            <tbody>{present_rows if present_rows else "<tr><td colspan='2'>No security headers detected.</td></tr>"}</tbody>
        </table>

        <h2>⚠️ Missing / Recommended Headers</h2>
        <table>
            <thead><tr><th>Missing Header</th><th>Recommendation</th></tr></thead>
            <tbody>{missing_rows if missing_rows else "<tr><td colspan='2'>All standard security headers are present.</td></tr>"}</tbody>
        </table>
    </div>
</body>
</html>
"""
        return html
