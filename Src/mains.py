import json
from pathlib import Path

from src.analyzer import analyze_event
from src.report_generator import generate_report


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    sample_path = project_root / "samples" / "cloudtrail_events.json"
    reports_dir = project_root / "reports"

    with sample_path.open("r", encoding="utf-8") as sample_file:
        events = json.load(sample_file)

    if not isinstance(events, list):
        raise ValueError("The sample file must contain a JSON list of events.")

    all_findings = []

    for event in events:
        if not isinstance(event, dict):
            print("Skipping an invalid event: expected a JSON object.")
            continue

        all_findings.extend(analyze_event(event))

    result = generate_report(all_findings, str(reports_dir))
    summary = result["report"]["summary"]

    print("Cloud Security Analysis Complete")
    print("--------------------------------")
    print(f"Events analyzed: {len(events)}")
    print(f"Findings generated: {summary['total_findings']}")
    print(f"HIGH: {summary['severity_counts']['HIGH']}")
    print(f"MEDIUM: {summary['severity_counts']['MEDIUM']}")
    print(f"LOW: {summary['severity_counts']['LOW']}")
    print(f"INFO: {summary['severity_counts']['INFO']}")
    print(f"JSON report saved to: {result['report_path']}")


if __name__ == "__main__":
    main()
