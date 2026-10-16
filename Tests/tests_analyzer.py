import unittest

from src.analyzer import analyze_event


class TestAnalyzeEvent(unittest.TestCase):

    def test_failed_console_login(self):
        event = {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.10",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
            },
            "responseElements": {
                "ConsoleLogin": "Failure",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(
            findings[0]["title"],
            "Failed AWS console sign-in",
        )
        self.assertEqual(findings[0]["rule_id"], "AUTH-001")

    def test_iam_policy_attachment(self):
        event = {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "203.0.113.20",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-admin",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(
            findings[0]["title"],
            "IAM permissions changed",
        )
        self.assertEqual(findings[0]["rule_id"], "IAM-001")

    def test_root_account_activity(self):
        event = {
            "eventName": "CreateUser",
            "sourceIPAddress": "203.0.113.30",
            "userIdentity": {
                "type": "Root",
                "principalId": "EXAMPLE-ROOT-IDENTITY",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(
            findings[0]["title"],
            "AWS root account activity detected",
        )
        self.assertEqual(findings[0]["rule_id"], "IDENTITY-001")

    def test_unmatched_event(self):
        event = {
            "eventName": "DescribeInstances",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertEqual(
            findings[0]["title"],
            "No configured detection rule matched",
        )
        self.assertEqual(findings[0]["rule_id"], "NO_MATCH")

    def test_failed_login_rule_id(self):
        event = {
            "eventName": "ConsoleLogin",
            "errorMessage": "Failed authentication",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(findings[0]["rule_id"], "AUTH-001")

    def test_iam_change_rule_id(self):
        event = {
            "eventName": "AttachUserPolicy",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-admin",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(findings[0]["rule_id"], "IAM-001")

    def test_root_activity_rule_id(self):
        event = {
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "Root",
                "principalId": "EXAMPLE-ROOT-IDENTITY",
            },
        }

        findings = analyze_event(event)

        self.assertEqual(findings[0]["rule_id"], "IDENTITY-001")

    def test_unmatched_event_rule_id(self):
        event = {
            "eventName": "DescribeInstances",
        }

        findings = analyze_event(event)

        self.assertEqual(findings[0]["rule_id"], "NO_MATCH")

    def test_root_iam_change_generates_multiple_findings(self):
        event = {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "203.0.113.40",
            "eventTime": "2026-10-16T10:00:00Z",
            "eventID": "synthetic-event-001",
            "userIdentity": {
                "type": "Root",
                "principalId": "EXAMPLE-ROOT-IDENTITY",
            },
        }

        findings = analyze_event(event)
        rule_ids = {finding["rule_id"] for finding in findings}

        self.assertEqual(len(findings), 2)
        self.assertEqual(rule_ids, {"IAM-001", "IDENTITY-001"})

    def test_event_metadata_is_preserved(self):
        event = {
            "eventName": "DescribeInstances",
            "eventTime": "2026-10-16T10:00:00Z",
            "eventID": "synthetic-event-002",
            "sourceIPAddress": "203.0.113.50",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
            },
        }

        findings = analyze_event(event)
        finding = findings[0]

        self.assertEqual(finding["event_time"], event["eventTime"])
        self.assertEqual(finding["event_id"], event["eventID"])
        self.assertEqual(finding["source_ip"], event["sourceIPAddress"])
        self.assertEqual(finding["user"], "test-user")


if __name__ == "__main__":
    unittest.main()
