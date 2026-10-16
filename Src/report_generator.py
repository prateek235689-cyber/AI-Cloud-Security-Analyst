import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(
    findings: list[dict[str, Any]],
    output_dir: str = "reports",
) -> dict[str, Any]:
    """
    Generate and save a structured JSON security investigation report.
    """
    generated_at = datetime.now(timezone.utc).isoformat()

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "report_version": "1.0",
        "generated_at": generated_at,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
        },
        "findings": findings,
    }

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = report_dir / f"security-report-{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)

    return {
        "report": report,
        "report_path": str(report_path),
    }
