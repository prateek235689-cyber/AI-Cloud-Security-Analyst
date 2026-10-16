import json
import tempfile
import unittest
from pathlib import Path

from src.report_generator import generate_report


class TestGenerateReport(unittest.TestCase):

    def setUp(self):
        self.findings = [
            {
                "rule_id": "IAM-001",
                "severity": "HIGH",
                "title": "IAM permissions changed",
            },
            {
                "rule_id": "AUTH-001",
                "severity": "MEDIUM",
                "title": "Failed AWS console sign-in",
            },
            {
                "rule_id": "IDENTITY-001",
                "severity": "HIGH",
                "title": "AWS root account activity detected",
            },
        ]

    def test_report_summary_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = generate_report(self.findings, temp_dir)

            summary = result["report"]["summary"]

            self.assertEqual(summary["total_findings"], 3)
            self.assertEqual(summary["severity_counts"]["HIGH"], 2)
            self.assertEqual(summary["severity_counts"]["MEDIUM"], 1)
            self.assertEqual(summary["severity_counts"]["LOW"], 0)
            self.assertEqual(summary["severity_counts"]["INFO"], 0)

    def test_json_report_is_saved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = generate_report(self.findings, temp_dir)

            report_path = Path(result["report_path"])

            self.assertTrue(report_path.exists())

            with report_path.open("r", encoding="utf-8") as report_file:
                saved_report = json.load(report_file)

            self.assertEqual(saved_report["summary"]["total_findings"], 3)
            self.assertEqual(len(saved_report["findings"]), 3)

    def test_findings_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = generate_report(self.findings, temp_dir)

            self.assertEqual(result["report"]["findings"], self.findings)

    def test_empty_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = generate_report([], temp_dir)

            self.assertEqual(result["report"]["summary"]["total_findings"], 0)
            self.assertEqual(
                result["report"]["summary"]["severity_counts"]["HIGH"],
                0,
            )
            self.assertEqual(result["report"]["findings"], [])


if __name__ == "__main__":
    unittest.main()
