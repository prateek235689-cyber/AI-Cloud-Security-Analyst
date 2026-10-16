import unittest

from src.analyzer import analyze_event


class TestAnalyzeEvent(unittest.TestCase):

    def test_failed_console_login(self):
        event = {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.10",
            "userIdentity": {"type": "IAMUser", "userName": "test-user"},
            "responseElements": {"ConsoleLogin": "Failure"},
        }

        result = analyze_event(event)

        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(result["title"], "Failed AWS console sign-in")

    def test_iam_policy_attachment(self):
        event = {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "203.0.113.20",
            "userIdentity": {"type": "IAMUser", "userName": "test-admin"},
        }

        result = analyze_event(event)

        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["title"], "IAM permissions changed")

    def test_unmatched_event(self):
        event = {
            "eventName": "DescribeInstances",
            "userIdentity": {"type": "IAMUser", "userName": "test-user"},
        }

        result = analyze_event(event)

        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(
            result["title"],
            "No configured detection rule matched",
        )


if __name__ == "__main__":
    unittest.main()
