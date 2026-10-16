# AI-Powered Cloud Security Analyst
A Python-based cloud security analysis prototype that examines AWS CloudTrail events, identifies selected security-relevant activities, and generates structured findings with severity levels and remediation recommendations.

> **Project status:** Rule-based prototype with three unit tests passing locally. This project does not currently provide live AWS monitoring or an implemented AI analysis layer.

## Project Overview:
Cloud environments generate audit events that can help security teams investigate suspicious sign-ins and changes to access permissions. Reviewing these events manually can be time-consuming.
This project demonstrates how Python can analyze individual CloudTrail event records using configurable detection rules and produce consistent security findings for investigation.

## Objectives:
- Analyze AWS CloudTrail event records using Python.
- Detect selected failed AWS console sign-ins.
- Identify IAM policy attachment and inline policy modification events.
- Assign severity levels to matched events.
- Generate investigation recommendations.
- Validate detection behavior with automated unit tests.
- Document AWS investigation evidence and remediation findings.

## Detection Capabilities:
| Event or activity | Detection result | Severity |
|---|---|---|
| Failed `ConsoleLogin` | Failed AWS console sign-in | MEDIUM |
| `AttachUserPolicy` | IAM permissions changed | HIGH |
| `AttachRolePolicy` | IAM permissions changed | HIGH |
| `AttachGroupPolicy` | IAM permissions changed | HIGH |
| `PutUserPolicy` | IAM permissions changed | HIGH |
| `PutRolePolicy` | IAM permissions changed | HIGH |
| `PutGroupPolicy` | IAM permissions changed | HIGH |
| Other unmatched events | No configured detection rule matched | INFO |

Severity levels are assigned by prototype rules. A HIGH finding indicates an activity that warrants review; it does not, by itself, prove malicious behavior.

## Technology Stack:
- **Python** — event parsing and detection logic
- **AWS CloudTrail** — audit-event investigation and evidence
- **AWS Identity and Access Management (IAM)** — permissions and policy review
- **Python unittest** — automated rule testing
- **GitHub** — source code, documentation, and project evidence

## How It Works:
1. An AWS CloudTrail event is supplied as a Python dictionary.
2. The analyzer extracts the event name, source IP address, and available user identity.
3. Configured rules inspect the event for selected security-relevant activities.
4. The analyzer returns a structured finding containing severity, title, description, and recommendation.
5. Unit tests validate expected results for representative synthetic events.

## Example Finding:
Illustrative output for an IAM policy attachment event:

```json
{
  "event_name": "AttachUserPolicy",
  "source_ip": "203.0.113.20",
  "user": "test-admin",
  "severity": "HIGH",
  "title": "IAM permissions changed",
  "description": "The event represents an IAM policy attachment or inline policy change that may affect access permissions.",
  "recommendation": "Verify the actor, target identity, policy and change approval. Check whether the resulting permissions follow least-privilege principles."
}
```

The IP address and username in this example are synthetic test data.

## Project Structure:
```text
AI-Cloud-Security-Analyst/
├── src/
│   └── analyzer.py
├── tests/
│   ├── __init__.py
│   └── test_analyzer.py
├── samples/
├── reports/
│   └── iam-policy-change-investigation.md
├── screenshots/
├── requirements.txt
├── .gitignore
└── README.md
```

The repository also contains screenshots documenting selected AWS Console investigation steps and local test results.

## Testing:
The current unit-test suite covers three scenarios:

1. Failed AWS console sign-in detection.
2. IAM policy attachment detection.
3. Handling of an event that does not match a configured rule.

**Current test result:** 3 of 3 tests passed locally.

Run the tests from the project root in an activated Python environment:

```cmd
python -m unittest discover -s tests -v
```

## AWS Investigation and Remediation:
The project documents an investigation of CloudTrail events related to console sign-in activity and an IAM policy attachment.
During the associated IAM policy review, an incorrect placeholder in the `s3:GetObject` resource was identified and corrected to reference the intended S3 bucket. The report documents the finding, remediation, verification evidence, and investigation limitations.
The policy correction demonstrates resource-scope review. It does not, by itself, establish the complete effective permissions of an IAM identity or prove that an event was malicious.

## Security Considerations:
- Use synthetic or sanitized event records in public examples.
- Do not publish AWS secret access keys, session tokens, passwords, or sensitive account information.
- Review screenshots and logs before uploading them to a public repository.
- Investigate HIGH-severity findings in context rather than treating them as proof of compromise.
- Use least-privilege IAM permissions and verify access changes before relying on them.

## Current Limitations:
- Rule-based analysis of individual event records; no continuous monitoring.
- No automatic ingestion of live CloudTrail events.
- No alerting pipeline is currently implemented.
- No AI-based explanation layer is currently implemented.
- Only the detection scenarios listed above are covered by the current unit tests.

## Future Enhancements:
- Add more CloudTrail detection rules and negative test cases.
- Add configurable detection thresholds and structured JSON report export.
- Explore a free, optional AI explanation layer with careful handling of sensitive data.
- Add automated testing through GitHub Actions.
- Evaluate safe ways to integrate AWS event data without exposing credentials or incurring unexpected cloud costs.

## Learning Outcomes:
This project demonstrates practical work with AWS audit events, IAM policy review, Python-based detection logic, unit testing, security findings, remediation documentation, and evidence-based investigation.

## Disclaimer:
This is an educational cloud security project. It is not a production security monitoring system and does not replace AWS-native security controls or a professional security investigation.
