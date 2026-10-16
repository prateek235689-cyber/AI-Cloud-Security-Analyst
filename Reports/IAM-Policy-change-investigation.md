# IAM Policy Change Investigation Report

## 1. Executive Summary:
A real AWS CloudTrail management event, `AttachUserPolicy`, was reviewed to investigate an IAM permission change. The event records a request to attach the managed policy `S3-Security-read-only-policy` to an IAM user.
The event was initiated using the AWS root identity, and the session context reports that MFA was authenticated. The event record contains no `errorCode`, but its `responseElements` value is null. The actual policy attachment should therefore be verified against the current IAM configuration or other available evidence.

**Initial assessment:** Requires verification. The event alone does not establish malicious activity.

## 2. Event Evidence:
| Field | Observed value |
|---|---|
| Event name | `AttachUserPolicy` |
| Event source | `iam.amazonaws.com` |
| Event category | Management |
| Event type | `AwsApiCall` |
| AWS Region | `us-east-1` |
| Target user | `S3-security-test-user` |
| Policy name | `S3-Security-read-only-policy` |
| Initiating identity | Root |
| MFA authenticated | `true` |
| Error code | Not present in the supplied record |
| Response elements | `null` |
| Session origin | AWS Management Console |

Sensitive account identifiers, access-key identifiers, source IP addresses, and request/event IDs are intentionally omitted.

## 3. Security Analysis:

### Potential concern: Root identity used for IAM administration
The root identity has broad account-level privileges. Its use to attach an IAM policy should be reviewed against the organization's administrative procedures and approved change records.
MFA authentication is a positive security control, but it does not independently prove that the action was authorized.

### Potential impact: Access permissions changed:
Attaching a managed IAM policy can change the effective permissions of the target user. The policy name suggests read-only S3 access, but the name alone does not establish the actual permissions.
The policy document and the user's other attached or inherited permissions must be reviewed before assessing the effective access.

### Event outcome:
The supplied record does not contain an `errorCode`. However, `responseElements` is null, so the attachment should be independently verified before the investigation records it as confirmed successful.

## 4. Recommended Investigation Steps:
1. Verify that the IAM policy attachment was expected and approved.
2. Inspect the managed policy document to identify the actions and resources it allows or denies.
3. Verify the target user's current policy attachments in the IAM console.
4. Review related CloudTrail activity around the event time for the initiating session and other permission changes.
5. Confirm that routine administration uses an appropriately privileged non-root identity wherever possible.
6. Document the verification results and any corrective actions.

## 5. Recommended Security Controls:
- Avoid using the root identity for routine administration.
- Maintain MFA protection for privileged identities.
- Follow least-privilege principles for IAM policies.
- Review and approve permission changes.
- Monitor IAM policy attachment and modification events.
- Keep security investigation evidence sanitized before publishing it.

## 6. Limitations:
This report is based on one CloudTrail event record. It does not establish malicious intent, prove that the policy grants only read-only access, or independently confirm the final IAM configuration.
No live remediation was performed as part of this investigation.

## 7. Conclusion:
The event provides useful evidence for an IAM permission-change investigation. The appropriate next action is to verify the authorization and resulting permissions, document the findings, and apply corrective measures only if a control gap is confirmed.
