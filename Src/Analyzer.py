from typing import Any


def analyze_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze one AWS CloudTrail event using basic security rules.
    This is a local, rule-based prototype—not a live AWS monitor.
    """
    event_name = event.get("eventName", "Unknown")
    source_ip = event.get("sourceIPAddress", "Unknown")
    user_identity = event.get("userIdentity", {})
    user_name = (
        user_identity.get("userName")
        or user_identity.get("principalId")
        or "Unknown"
    )

    finding = {
        "event_name": event_name,
        "source_ip": source_ip,
        "user": user_name,
        "severity": "INFO",
        "title": "No configured detection rule matched",
        "description": "The event did not match the current prototype rules.",
        "recommendation": "Review the event in context if it is unexpected.",
    }

    if event_name == "ConsoleLogin" and event.get("errorMessage"):
        finding.update({
            "severity": "MEDIUM",
            "title": "Failed AWS console sign-in",
            "description": (
                "The event contains an error message, indicating "
                "that the console sign-in did not succeed."
            ),
            "recommendation": (
                "Verify whether the attempt was expected. Review related "
                "sign-in events and investigate repeated failures."
            ),
        })

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

    return finding
