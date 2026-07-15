"""
HTML Report Generator for GMS Certification Results
Generates visual HTML reports for GMS certification checks.
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import asdict


class GMSReportGenerator:
    """
    Generates HTML reports for GMS certification check results.
    """

    def __init__(self, title: str = "GMS Certification Report"):
        self.title = title

    def generate_report(
        self,
        check_result: Dict[str, Any],
        device_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a complete HTML report."""

        status = check_result.get("status", "unknown")
        is_certified = check_result.get("is_certified", False)

        status_color = "#4CAF50" if is_certified else "#f44336"
        status_text = "GMS CERTIFIED" if is_certified else "NOT CERTIFIED"
        status_icon = "✅" if is_certified else "❌"

        components = check_result.get("components_found", [])
        missing = check_result.get("missing_components", [])
        suspicious = check_result.get("suspicious_packages", [])
        warnings = check_result.get("warnings", [])
        errors = check_result.get("errors", [])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 900px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a73e8, #4285f4); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .header .timestamp {{ opacity: 0.8; font-size: 13px; }}
        .status-card {{ background: white; border-radius: 12px; padding: 30px; margin-bottom: 20px; text-align: center; }}
        .status-badge {{ display: inline-block; padding: 12px 30px; border-radius: 30px; font-size: 18px; font-weight: bold; color: white; background: {status_color}; }}
        .confidence {{ margin-top: 10px; font-size: 13px; color: #666; }}
        .card {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .card h2 {{ font-size: 16px; color: #666; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .component-list {{ list-style: none; }}
        .component-list li {{ padding: 10px 0; border-bottom: 1px solid #eee; display: flex; align-items: center; }}
        .component-list li:last-child {{ border-bottom: none; }}
        .icon {{ width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 12px; font-size: 12px; }}
        .icon.success {{ background: #e8f5e9; color: #4CAF50; }}
        .icon.error {{ background: #ffebee; color: #f44336; }}
        .icon.warning {{ background: #fff3e0; color: #ff9800; }}
        .versions {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }}
        .version-box {{ background: #f8f9fa; border-radius: 8px; padding: 16px; text-align: center; }}
        .version-box .label {{ font-size: 11px; color: #666; text-transform: uppercase; margin-bottom: 4px; }}
        .version-box .value {{ font-size: 16px; font-weight: bold; color: #1a73e8; }}
        .warnings-box, .errors-box {{ background: #fff8e1; border-left: 4px solid #ff9800; padding: 16px; border-radius: 4px; margin-top: 12px; }}
        .errors-box {{ background: #ffebee; border-color: #f44336; }}
        .progress {{ background: #e0e0e0; border-radius: 10px; height: 20px; overflow: hidden; margin-top: 10px; }}
        .progress-fill {{ height: 100%; border-radius: 10px; background: linear-gradient(90deg, #4CAF50, #8BC34A); }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 600px) {{ .grid-2 {{ grid-template-columns: 1fr; }} .versions {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>{self.title}</h1>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>

    <div class="status-card">
        <div class="status-badge">{status_icon} {status_text}</div>
        <div class="confidence">Confidence: {check_result.get('confidence', 0) * 100:.0f}%</div>
        <div class="progress">
            <div class="progress-fill" style="width: {check_result.get('confidence', 0) * 100:.0f}%"></div>
        </div>
    </div>

    <div class="versions">
        <div class="version-box">
            <div class="label">Play Store</div>
            <div class="value">{check_result.get('play_store_version') or 'N/A'}</div>
        </div>
        <div class="version-box">
            <div class="label">Play Services</div>
            <div class="value">{check_result.get('play_services_version') or 'N/A'}</div>
        </div>
        <div class="version-box">
            <div class="label">GSF</div>
            <div class="value">{check_result.get('gsf_version') or 'N/A'}</div>
        </div>
    </div>

    <div class="card" style="margin-top: 20px;">
        <h2>Found GMS Components ({len(components)})</h2>
        <ul class="component-list">
"""
        for comp in components:
            html += f'            <li><span class="icon success">✅</span>{comp}</li>\n'

        html += f"""        </ul>
"""

        if missing:
            html += f"""
        <h2 style="margin-top: 20px;">Missing Components ({len(missing)})</h2>
        <ul class="component-list">
"""
            for pkg in missing:
                html += f'            <li><span class="icon error">❌</span>{pkg}</li>\n'

        if suspicious:
            html += f"""
        <h2 style="margin-top: 20px;">Suspicious Packages ({len(suspicious)})</h2>
        <ul class="component-list">
"""
            for pkg in suspicious:
                html += f'            <li><span class="icon warning">⚠️</span>{pkg}</li>\n'

        html += """        </ul>
    </div>
"""

        if errors or warnings:
            html += '<div class="card">\n'
            if errors:
                html += '<div class="errors-box">'
                for e in errors:
                    html += f'<div>❌ {e}</div>'
                html += '</div>\n'
            if warnings:
                html += '<div class="warnings-box">'
                for w in warnings:
                    html += f'<div>⚠️ {w}</div>'
                html += '</div>\n'
            html += '</div>\n'

        html += f"""
    <div class="card">
        <h2>Summary</h2>
        <p><strong>Status:</strong> {status.upper()}</p>
        <p><strong>Certified:</strong> {'Yes' if is_certified else 'No'}</p>
        <p><strong>Google Account Linked:</strong> {'Yes' if check_result.get('google_account_linked') else 'No'}</p>
        <p><strong>Components Found:</strong> {len(components)}</p>
        <p><strong>Missing:</strong> {len(missing)}</p>
        <p><strong>Suspicious:</strong> {len(suspicious)}</p>
    </div>

    <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
        Report generated by GMS Certification Checker | qtphone.com
    </div>
</div>
</body>
</html>
"""
        return html

    def save_report(self, output_path: str, check_result: Dict[str, Any]):
        """Save the HTML report to a file."""
        html = self.generate_report(check_result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="GMS HTML Report Generator")
    parser.add_argument("--input-json", help="Path to JSON result file")
    parser.add_argument("--output", default="gms_report.html", help="Output HTML path")
    args = parser.parse_args()

    if args.input_json:
        with open(args.input_json) as f:
            check_result = json.load(f)
    else:
        check_result = {
            "status": "unknown",
            "is_certified": False,
            "confidence": 0.0,
            "components_found": [],
            "missing_components": [],
            "suspicious_packages": [],
            "warnings": [],
            "errors": [],
        }

    generator = GMSReportGenerator()
    generator.save_report(args.output, check_result)
    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
