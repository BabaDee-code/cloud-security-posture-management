# Cloud Security Posture Management

![CI](https://github.com/BabaDee-code/cloud-security-posture-management/actions/workflows/ci.yml/badge.svg)

A lightweight cloud security posture management project that scans cloud configuration snapshots for public exposure, weak IAM, missing encryption, insecure network rules, and logging gaps. This portfolio project uses sample data and deterministic checks so the findings are testable and safe to run locally.

## What this project shows

- Cloud configuration risk assessment
- S3/public storage exposure checks
- IAM policy risk detection
- Security group exposure analysis across IPv4 and IPv6
- Administrative-port detection for single ports and port ranges
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

## Supported security-group rule shapes

The scanner recognizes internet-wide IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) exposure. Ingress rules may specify either a single port or an inclusive range:

```json
{"port": 22, "cidr": "0.0.0.0/0"}
```

```json
{"from_port": 20, "to_port": 25, "cidr": "::/0"}
```

Ranges containing SSH (22) or RDP (3389) are treated as critical administrative exposure even when the administrative port is not a range boundary.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
PYTHONPATH=src pytest -q
PYTHONPATH=src python -m cspm.scan data/aws_snapshot.json
```

## Example finding

```json
{
  "resource_id": "sg-001",
  "severity": "critical",
  "finding": "Security group allows internet access to administrative port(s) 22",
  "recommendation": "Restrict administrative access to approved corporate ranges or a managed access service."
}
```

## Portfolio talking points

This project demonstrates practical cloud security engineering by converting cloud configuration data into prioritized, remediation-ready security findings. It shows how I approach CSPM-style checks, IPv4/IPv6 exposure analysis, risk scoring, and audit-friendly reporting.
