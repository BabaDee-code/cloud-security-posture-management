# Cloud Security Control Mapping

## Objective

Convert cloud configuration snapshots into prioritized findings that support security engineering, audit readiness, and remediation planning.

## Control areas

| Control Area | Scanner Coverage |
|---|---|
| Public exposure | Public storage buckets and internet-exposed security group rules |
| IAM least privilege | Wildcard actions and wildcard resources |
| Encryption | Storage encryption validation |
| Logging and monitoring | Account-level audit logging and retention checks |
| Remediation readiness | Each finding includes a recommendation |

## Severity model

- `critical`: public administrative access, public sensitive storage, or wildcard admin-style IAM
- `high`: missing encryption, disabled audit logging, or broad IAM actions
- `medium`: general public exposure or insufficient log retention

## Employer-facing explanation

This repository demonstrates a CSPM-style approach to cloud security: collect configuration context, evaluate it against security controls, prioritize risk, and generate remediation guidance that engineers can act on.
