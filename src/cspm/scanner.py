from __future__ import annotations

from typing import Any

ADMIN_PORTS = {22, 3389}
INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def scan_snapshot(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    """Scan a cloud configuration snapshot for common posture risks."""
    findings: list[dict[str, str]] = []
    findings.extend(_scan_storage(snapshot.get("storage_buckets", [])))
    findings.extend(_scan_security_groups(snapshot.get("security_groups", [])))
    findings.extend(_scan_iam_policies(snapshot.get("iam_policies", [])))
    findings.extend(_scan_logging(snapshot.get("account_logging", {})))
    return findings


def _scan_storage(buckets: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings = []
    for bucket in buckets:
        resource_id = str(bucket.get("name", "unknown-bucket"))
        if bucket.get("public_access") is True:
            findings.append(_finding(resource_id, "critical", "Storage bucket allows public access", "Disable public access and require explicit approved sharing."))
        if bucket.get("encryption") is not True:
            findings.append(_finding(resource_id, "high", "Storage bucket encryption is not enabled", "Enable default encryption using managed or customer-managed keys."))
    return findings


def _scan_security_groups(groups: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings = []
    for group in groups:
        resource_id = str(group.get("id", "unknown-sg"))
        for rule in group.get("ingress", []):
            cidr = str(rule.get("cidr", ""))
            if cidr not in INTERNET_CIDRS:
                continue

            port_range = _port_range(rule)
            if port_range is None:
                continue

            start_port, end_port = port_range
            exposed_admin_ports = sorted(port for port in ADMIN_PORTS if start_port <= port <= end_port)

            if exposed_admin_ports:
                admin_ports = ", ".join(str(port) for port in exposed_admin_ports)
                findings.append(
                    _finding(
                        resource_id,
                        "critical",
                        f"Security group allows internet access to administrative port(s) {admin_ports}",
                        "Restrict administrative access to approved corporate ranges or a managed access service.",
                    )
                )
            else:
                port_label = str(start_port) if start_port == end_port else f"{start_port}-{end_port}"
                findings.append(
                    _finding(
                        resource_id,
                        "medium",
                        f"Security group allows internet access to port(s) {port_label}",
                        "Confirm business need and restrict exposure where possible.",
                    )
                )
    return findings


def _port_range(rule: dict[str, Any]) -> tuple[int, int] | None:
    """Normalize supported ingress rule shapes into an inclusive port range."""
    if "port" in rule:
        port = _as_port(rule.get("port"))
        return (port, port) if port is not None else None

    start_port = _as_port(rule.get("from_port"))
    end_port = _as_port(rule.get("to_port"))
    if start_port is None or end_port is None:
        return None
    if start_port > end_port:
        start_port, end_port = end_port, start_port
    return start_port, end_port


def _as_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def _scan_iam_policies(policies: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings = []
    for policy in policies:
        resource_id = str(policy.get("name", "unknown-policy"))
        actions = set(policy.get("actions", []))
        resources = set(policy.get("resources", []))
        if "*" in actions and "*" in resources:
            findings.append(_finding(resource_id, "critical", "IAM policy allows wildcard actions on wildcard resources", "Replace wildcard permissions with least-privilege actions and scoped resources."))
        elif "*" in actions:
            findings.append(_finding(resource_id, "high", "IAM policy allows wildcard actions", "Limit permissions to the minimum required actions."))
    return findings


def _scan_logging(logging_config: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    if logging_config.get("cloudtrail_enabled") is not True:
        findings.append(_finding("account_logging", "high", "CloudTrail-style audit logging is disabled", "Enable account-level audit logging across all regions."))
    if logging_config.get("log_retention_days", 0) < 90:
        findings.append(_finding("account_logging", "medium", "Log retention is shorter than 90 days", "Increase retention to meet investigation and compliance requirements."))
    return findings


def _finding(resource_id: str, severity: str, finding: str, recommendation: str) -> dict[str, str]:
    return {
        "resource_id": resource_id,
        "severity": severity,
        "finding": finding,
        "recommendation": recommendation,
    }
