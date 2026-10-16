
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

        result = analyze_event(event)

        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(
            result["title"],
            "Failed AWS console sign-in",
        )

    def test_iam_policy_attachment(self):
        event = {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "203.0.113.20",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-admin",
            },
        }

        result = analyze_event(event)

        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(
            result["title"],
            "IAM permissions changed",
        )

    def test_root_account_activity(self):
        event = {
            "eventName": "CreateUser",
            "sourceIPAddress": "203.0.113.30",
            "userIdentity": {
                "type": "Root",
                "principalId": "EXAMPLE-ROOT-IDENTITY",
            },
        }

        result = analyze_event(event)

        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(
            result["title"],
            "AWS root account activity detected",
        )

    def test_unmatched_event(self):
        event = {
            "eventName": "DescribeInstances",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
            },
        }

        result = analyze_event(event)

        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(
            result["title"],
            "No configured detection rule matched",
        )

    def test_failed_login_rule_id(self):
        event = {
            "eventName": "ConsoleLogin",
            "errorMessage": "Failed authentication",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
            },
        }

        self.assertEqual(
            analyze_event(event)["rule_id"],
            "AUTH-001",
        )

    def test_iam_change_rule_id(self):
        event = {
            "eventName": "AttachUserPolicy",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-admin",
            },
        }

        self.assertEqual(
            analyze_event(event)["rule_id"],
            "IAM-001",
        )

    def test_root_activity_rule_id(self):
        event = {
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "Root",
                "principalId": "EXAMPLE-ROOT-IDENTITY",
            },
        }

        self.assertEqual(
            analyze_event(event)["rule_id"],
            "IDENTITY-001",
        )

    def test_unmatched_event_rule_id(self):
        event = {
            "eventName": "DescribeInstances",
        }

        self.assertEqual(
            analyze_event(event)["rule_id"],
            "NO_MATCH",
        )


if __name__ == "__main__":
    unittest.main()
