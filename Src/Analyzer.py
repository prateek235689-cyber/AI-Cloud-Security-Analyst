
from typing import Any


def analyze_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze one AWS CloudTrail event using basic security rules.
    This is a local, rule-based prototype—not a live AWS monitor.
    """
    event_name = event.get("eventName", "Unknown")
    source_ip = event.get("sourceIPAddress", "Unknown")
    user_identity = event.get("userIdentity", {})

    if not isinstance(user_identity, dict):
        user_identity = {}

    user_name = (
        user_identity.get("userName")
        or user_identity.get("principalId")
        or "Unknown"
    )
    identity_type = user_identity.get("type", "Unknown")

    finding = {
        "event_name": event_name,
        "source_ip": source_ip,
        "user": user_name,
        "severity": "INFO",
        "title": "No configured detection rule matched",
        "description": "The event did not match the current prototype rules.",
        "recommendation": "Review the event in context if it is unexpected.",
    }

    # Rule 1: Detect failed AWS console sign-ins.
    if (
        event_name == "ConsoleLogin"
        and (
            event.get("errorMessage")
            or (
                isinstance(event.get("responseElements"), dict)
                and event["responseElements"].get("ConsoleLogin") == "Failure"
            )
        )
    ):
        finding.update({
            "severity": "MEDIUM",
            "title": "Failed AWS console sign-in",
            "description": (
                "The event indicates that the AWS console sign-in failed, "
                "based on its error message or failure status."
            ),
            "recommendation": (
                "Verify whether the attempt was expected. Review related "
                "sign-in events and investigate repeated failures."
            ),
        })

    # Rule 2: Detect IAM policy changes.
    elif event_name in {
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
    }:
        finding.update({
            "severity": "HIGH",
            "title": "IAM permissions changed",
            "description": (
                "The event represents an IAM policy attachment or "
                "inline policy change that may affect access permissions."
            ),
            "recommendation": (
                "Verify the actor, target identity, policy and change "
                "approval. Check whether the resulting permissions "
                "follow least-privilege principles."
            ),
        })

    # Rule 3: Flag activity performed by the AWS root identity.
    elif identity_type == "Root":
        finding.update({
            "severity": "HIGH",
            "title": "AWS root account activity detected",
            "description": (
                "The CloudTrail event identifies the actor as the AWS "
                "root identity. Root activity is sensitive and requires "
                "contextual review; it is not automatically malicious."
            ),
            "recommendation": (
                "Verify whether the activity was necessary and authorized. "
                "Review the event name, time, source and related activity. "
                "Prefer an appropriately scoped IAM identity for routine "
                "administration."
            ),
        })

    return finding
