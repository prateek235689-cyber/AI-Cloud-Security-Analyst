import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import analyze_event
from src.report_generator import generate_report


class TestCloudSecurityPipeline(unittest.TestCase):

    def test_sample_events_generate_expected_findings(self):
        project_root = Path(__file__).resolve().parent.parent
        sample_path = project_root / "samples" / "cloudtrail_events.json"

        with sample_path.open("r", encoding="utf-8") as sample_file:
            events = json.load(sample_file)

        all_findings = []

        for event in events:
            all_findings.extend(analyze_event(event))

        self.assertEqual(len(events), 4)
        self.assertEqual(len(all_findings), 5)

        severity_counts = {
            "HIGH": sum(
                finding["severity"] == "HIGH"
                for finding in all_findings
            ),
            "MEDIUM": sum(
                finding["severity"] == "MEDIUM"
                for finding in all_findings
            ),
            "INFO": sum(
                finding["severity"] == "INFO"
                for finding in all_findings
            ),
        }

        self.assertEqual(severity_counts["HIGH"], 3)
        self.assertEqual(severity_counts["MEDIUM"], 1)
        self.assertEqual(severity_counts["INFO"], 1)

        root_findings = [
            finding
            for finding in all_findings
            if finding["event_id"] == "synthetic-event-004"
        ]

        self.assertEqual(len(root_findings), 2)
        self.assertEqual(
            {finding["rule_id"] for finding in root_findings},
            {"IAM-001", "IDENTITY-001"},
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            result = generate_report(all_findings, temp_dir)
            report_path = Path(result["report_path"])

            self.assertTrue(report_path.exists())

            with report_path.open("r", encoding="utf-8") as report_file:
                saved_report = json.load(report_file)

            self.assertEqual(
                saved_report["summary"]["total_findings"],
                5,
            )
            self.assertEqual(
                saved_report["summary"]["severity_counts"]["HIGH"],
                3,
            )


if __name__ == "__main__":
    unittest.main()
