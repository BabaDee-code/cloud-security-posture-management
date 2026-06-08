# Cloud Security Posture Management

![CI](https://github.com/BabaDee-code/cloud-security-posture-management/actions/workflows/ci.yml/badge.svg)

A lightweight cloud security posture management project that scans cloud configuration snapshots for public exposure, weak IAM, missing encryption, insecure network rules, and logging gaps. This portfolio project uses sample data and deterministic checks so the findings are testable and safe to run locally.

## What this project shows

- Cloud configuration risk assessment
- S3/public storage exposure checks
- IAM policy risk detection
- Security group exposure analysis
- Encryption and logging validation
- Risk scoring and remediation recommendations
- Unit tests and CI validation

## Repository structure

```text
src/cspm/                   Cloud posture scanner
data/aws_snapshot.json      Sample cloud configuration snapshot
tests/                      Unit tests
.github/workflows/ci.yml    Automated test workflow
docs/control-mapping.md     Security control mapping
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
pytest -q
python -m cspm.scan data/aws_snapshot.json
```

## Example finding

```json
{
  "resource_id": "sg-001",
  "severity": "critical",
  "finding": "Security group allows internet access to administrative port 22",
  "recommendation": "Restrict SSH access to approved corporate ranges or use a managed access service."
}
```

## Portfolio talking points

This project demonstrates practical cloud security engineering by converting cloud configuration data into prioritized, remediation-ready security findings. It shows how I approach CSPM-style checks, risk scoring, and audit-friendly reporting.
