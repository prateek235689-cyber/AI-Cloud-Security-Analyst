# AI-Powered Cloud Security Analyst
A Python-based cloud security analysis prototype that examines AWS CloudTrail events, detects selected security-relevant activities, assigns severity levels, and generates structured findings with investigation recommendations. The project includes automated unit tests and JSON security report generation.

> **Project status:** Working rule-based prototype. The current local test suite contains 14 passing tests. JSON report generation is implemented. Live AWS monitoring and an AI-powered analysis layer have not yet been implemented.

## Project Overview:
AWS CloudTrail records activity across an AWS environment, providing valuable evidence for security investigations. Reviewing audit events manually can be time-consuming, particularly when investigating authentication failures, permission changes, and privileged account activity.
This project demonstrates how Python can analyze CloudTrail event records using independent detection rules, produce structured security findings, and export investigation results into JSON reports. It also documents an IAM policy review and remediation exercise based on AWS Console investigation evidence.
The project is designed as a practical learning and portfolio project focused on cloud security, IAM, audit-event analysis, and security automation.

## Objectives:
- Analyze AWS CloudTrail event records using Python.
- Detect selected failed AWS console sign-ins.
- Identify IAM policy attachment and inline policy modification events.
- Flag events performed by the AWS root identity for contextual review.
- Generate multiple findings when an event matches multiple rules.
- Assign severity levels and provide investigation recommendations.
- Export structured security reports in JSON format.
- Validate detection and reporting behavior through automated unit tests.
- Document investigation evidence, findings, and remediation steps.

## Key Features:
- **Rule-based detection:** Identifies selected authentication and IAM-related activities.
- **Independent detection rules:** Allows a single event to trigger multiple findings.
- **Severity classification:** Assigns HIGH, MEDIUM, or INFO severity based on the configured rules.
- **Structured findings:** Includes event metadata, rule identifiers, descriptions, and recommendations.
- **JSON report generation:** Saves timestamped reports with finding summaries and severity counts.
- **Automated testing:** Uses Python's built-in `unittest` framework.
- **Investigation documentation:** Records selected AWS Console findings, policy review, and remediation evidence.

## Detection Capabilities:
| Rule ID | Event or activity | Detection result | Severity |
|---|---|---|---|
| `AUTH-001` | Failed `ConsoleLogin` | Failed AWS console sign-in | MEDIUM |
| `IAM-001` | `AttachUserPolicy` | IAM permissions changed | HIGH |
| `IAM-001` | `AttachRolePolicy` | IAM permissions changed | HIGH |
| `IAM-001` | `AttachGroupPolicy` | IAM permissions changed | HIGH |
| `IAM-001` | `PutUserPolicy` | IAM permissions changed | HIGH |
| `IAM-001` | `PutRolePolicy` | IAM permissions changed | HIGH |
| `IAM-001` | `PutGroupPolicy` | IAM permissions changed | HIGH |
| `IDENTITY-001` | Event performed by an AWS root identity | AWS root account activity detected | HIGH |
| `NO_MATCH` | No configured rule matches | No configured detection rule matched | INFO |

**Severity interpretation:** These severity levels are assigned by the project's configured rules. A HIGH finding indicates an activity that warrants review; it does not establish that the activity is malicious.
Root identity activity is flagged independently. Therefore, an event involving both an IAM policy change and a root identity can generate two findings.

## Technology Stack:
- **Python** — event analysis, detection logic, and report generation
- **AWS CloudTrail** — audit-event investigation and evidence
- **AWS Identity and Access Management (IAM)** — policy review and access-control concepts
- **JSON** — structured security findings and reports
- **Python `unittest`** — automated testing
- **GitHub** — source code, documentation, and project evidence

## How It Works:
1. A CloudTrail event is provided to the analyzer as a Python dictionary.
2. The analyzer extracts available event metadata, including the event name, timestamp, event ID, source IP address, and user identity.
3. Independent rules inspect the event for selected authentication failures, IAM policy changes, and root identity activity.
4. Each matching rule produces a structured finding containing a rule ID, severity, title, description, and recommendation.
5. Events that match no configured rule receive an informational finding.
6. The report generator collects findings, calculates severity counts, and creates a timestamped JSON report.
7. Automated tests validate the detection rules and report-generation behavior.

## Example Security Finding:
The following is illustrative output using synthetic test data:
```json
{
  "event_id": "synthetic-event-001",
  "event_time": "2026-10-16T10:00:00Z",
  "event_name": "AttachUserPolicy",
  "source_ip": "203.0.113.40",
  "user": "EXAMPLE-ROOT-IDENTITY",
  "rule_id": "IAM-001",
  "severity": "HIGH",
  "title": "IAM permissions changed",
  "description": "The event represents an IAM policy attachment or inline policy change that may affect access permissions.",
  "recommendation": "Verify the actor, target identity, policy and change approval. Check whether the resulting permissions follow least-privilege principles."
}
```
The event ID, timestamp, IP address, and identity shown above are synthetic examples. Real event details should be sanitized before publication.

## JSON Security Report:
The report generator in `src/report_generator.py` creates a structured JSON report containing:

- Report version and generation timestamp
- Total number of findings
- Counts grouped by severity
- Complete finding details
- A timestamped output file saved in the configured reports directory

Illustrative report structure:
```json
{
  "report_version": "1.0",
  "generated_at": "2026-10-16T10:30:00+00:00",
  "summary": {
    "total_findings": 2,
    "severity_counts": {
      "HIGH": 2,
      "MEDIUM": 0,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "rule_id": "IAM-001",
      "severity": "HIGH",
      "title": "IAM permissions changed"
    },
    {
      "rule_id": "IDENTITY-001",
      "severity": "HIGH",
      "title": "AWS root account activity detected"
    }
  ]
}
```
This example is abbreviated for readability. Actual reports preserve the finding details supplied to the report generator. The example timestamp and findings are illustrative.

## Project Structure:
```text
AI-Cloud-Security-Analyst/
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   └── report_generator.py
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py
│   └── test_report_generator.py
├── samples/
│   └── cloudtrail_events.json
├── reports/
│   └── iam-policy-change-investigation.md
├── screenshots/
├── requirements.txt
├── .gitignore
└── README.md
```
The `samples/` directory is intended for synthetic or sanitized CloudTrail events. The `reports/` directory contains investigation documentation and may also contain locally generated JSON reports. Generated reports should be reviewed before being committed to a public repository.

## Automated Testing:
The current local test suite contains **14 passing tests**:
- Failed console sign-in detection
- IAM policy change detection
- AWS root identity activity detection
- Handling unmatched events
- Rule ID validation
- Multiple findings generated from a single event
- Event metadata preservation
- JSON report file creation
- Severity count calculation
- Preservation of findings in the report
- Empty-report handling

### Run the tests:
From the project root, with Python available in your environment, run:
```bash
python -m unittest discover -s tests -v
```
**Verified local result:** 14 tests passed, with no failures or errors, in the most recently reported test run. This result describes the local run and is not a claim that GitHub Actions or another CI service has run the tests.

## AWS Investigation and Remediation:
The project includes documented AWS Console investigation work involving console sign-in activity and an IAM policy attachment.
During an IAM policy review, an incorrect placeholder in the `s3:GetObject` resource was identified and corrected to reference the intended S3 bucket. The investigation report documents the finding, remediation, verification evidence, and relevant limitations.
This exercise demonstrates the importance of checking IAM resource scope and reviewing access changes carefully. A policy correction alone does not establish the complete effective permissions of an identity or prove that an event was malicious.

## Security Considerations:
- Use synthetic or sanitized event records in public examples.
- Never publish AWS secret access keys, session tokens, passwords, or other credentials.
- Review screenshots, JSON reports, and logs before uploading them to a public repository.
- Avoid exposing sensitive account identifiers or unnecessary personal information.
- Treat HIGH-severity findings as investigation leads, not proof of compromise.
- Verify IAM policy changes and resulting permissions before relying on them.
- Use least-privilege permissions for routine AWS administration.

## Current Limitations:
- The analyzer evaluates individual event records; it does not continuously monitor an AWS environment.
- Live CloudTrail ingestion is not implemented.
- Automated notifications and alerting are not implemented.
- The analysis engine uses configured rules, not an implemented AI model.
- Detection coverage is limited to the events listed in this README.
- The prototype does not automatically determine whether an event is malicious.
- The project has not been presented as a production-ready security monitoring system.

## Future Enhancements:
- Add further CloudTrail detection rules and negative test cases.
- Make detection rules and severity thresholds configurable.
- Add a sanitized sample-event collection and reproducible demonstration workflow.
- Explore a free, optional AI explanation layer that can summarize findings without exposing sensitive data.
- Add automated testing through GitHub Actions.
- Evaluate safe, cost-conscious options for integrating AWS event data.
- Improve reporting with filtering, investigation summaries, and additional evidence references.

## Learning Outcomes:
This project demonstrates practical learning in:
- AWS CloudTrail event analysis
- AWS IAM policy review and least-privilege concepts
- Python-based security detection
- Multiple-rule evaluation and structured findings
- JSON report generation
- Automated unit testing
- Investigation documentation and remediation evidence
- Secure handling of public portfolio artifacts

## Disclaimer:
This is an educational cloud security prototype. It is not a production security monitoring system, does not provide live threat detection, and does not replace AWS-native security controls or a professional security investigation.
