from cspm.scanner import scan_snapshot


def test_public_unencrypted_bucket_generates_findings():
    findings = scan_snapshot({"storage_buckets": [{"name": "bucket1", "public_access": True, "encryption": False}]})
    finding_names = {finding["finding"] for finding in findings}
    assert "Storage bucket allows public access" in finding_names
    assert "Storage bucket encryption is not enabled" in finding_names


def test_admin_port_open_to_internet_is_critical():
    findings = scan_snapshot({"security_groups": [{"id": "sg-1", "ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]}]})
    assert findings[0]["severity"] == "critical"
    assert "administrative port 22" in findings[0]["finding"]


def test_ipv6_admin_port_open_to_internet_is_critical():
    findings = scan_snapshot({"security_groups": [{"id": "sg-v6-admin", "ingress": [{"port": 3389, "cidr": "::/0"}]}]})
    assert findings[0]["severity"] == "critical"
    assert "administrative port 3389" in findings[0]["finding"]


def test_ipv6_non_admin_port_open_to_internet_is_medium():
    findings = scan_snapshot({"security_groups": [{"id": "sg-v6-web", "ingress": [{"port": 443, "cidr": "::/0"}]}]})
    assert findings[0]["severity"] == "medium"
    assert "port 443" in findings[0]["finding"]


def test_private_ipv6_range_is_not_treated_as_internet_wide():
    findings = scan_snapshot({"security_groups": [{"id": "sg-v6-private", "ingress": [{"port": 22, "cidr": "fd00::/8"}]}]})
    assert findings == []


def test_wildcard_iam_policy_is_critical():
    findings = scan_snapshot({"iam_policies": [{"name": "bad", "actions": ["*"], "resources": ["*"]}]})
    assert findings[0]["severity"] == "critical"
    assert "wildcard actions" in findings[0]["finding"]


def test_disabled_logging_generates_finding():
    findings = scan_snapshot({"account_logging": {"cloudtrail_enabled": False, "log_retention_days": 30}})
    assert len(findings) == 2
