from typing import Any


def analyze_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Analyze one AWS CloudTrail event using independent security rules.

    Returns a list of findings because multiple rules can match one event.
    This is a local, rule-based prototype—not a live AWS monitor.
    """
    event_name = event.get("eventName", "Unknown")
    source_ip = event.get("sourceIPAddress", "Unknown")
    event_time = event.get("eventTime", "Unknown")
    event_id = event.get("eventID", "Unknown")

    user_identity = event.get("userIdentity", {})
    if not isinstance(user_identity, dict):
        user_identity = {}

    user_name = (
        user_identity.get("userName")
        or user_identity.get("principalId")
        or "Unknown"
    )
    identity_type = user_identity.get("type", "Unknown")

    findings: list[dict[str, Any]] = []

    # Shared event metadata included in every finding.
    metadata = {
        "event_id": event_id,
        "event_time": event_time,
        "event_name": event_name,
        "source_ip": source_ip,
        "user": user_name,
    }

    # Rule 1: Detect failed AWS console sign-ins.
    is_failed_login = (
        event_name == "ConsoleLogin"
        and (
            bool(event.get("errorMessage"))
            or (
                isinstance(event.get("responseElements"), dict)
                and event["responseElements"].get("ConsoleLogin") == "Failure"
            )
        )
    )

    if is_failed_login:
        findings.append({
            **metadata,
            "rule_id": "AUTH-001",
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
    iam_change_events = {
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
    }

    if event_name in iam_change_events:
        findings.append({
            **metadata,
            "rule_id": "IAM-001",
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

    # Rule 3: Flag AWS root identity activity independently.
    if identity_type == "Root":
        findings.append({
            **metadata,
            "rule_id": "IDENTITY-001",
            "severity": "HIGH",
            "title": "AWS root account activity detected",
            "description": (
                "The CloudTrail event identifies the actor as the AWS "
                "root identity. This activity requires contextual review "
                "and is not automatically malicious."
            ),
            "recommendation": (
                "Verify whether the activity was necessary and authorized. "
                "Review the event time, source and related activity. "
                "Prefer a suitably scoped IAM identity for routine work."
            ),
        })

    # Return an informational finding if no rule matched.
    if not findings:
        findings.append({
            **metadata,
            "rule_id": "NO_MATCH",
            "severity": "INFO",
            "title": "No configured detection rule matched",
            "description": (
                "The event did not match the current prototype rules."
            ),
            "recommendation": (
                "Review the event in context if it is unexpected."
            ),
        })

    return findings
