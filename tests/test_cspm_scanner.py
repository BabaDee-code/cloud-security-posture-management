from cspm.scanner import scan_snapshot


def test_public_unencrypted_bucket_generates_findings():
    findings = scan_snapshot({"storage_buckets": [{"name": "bucket1", "public_access": True, "encryption": False}]})
    finding_names = {finding["finding"] for finding in findings}
    assert "Storage bucket allows public access" in finding_names
    assert "Storage bucket encryption is not enabled" in finding_names


def test_admin_port_open_to_internet_is_critical():
    findings = scan_snapshot({"security_groups": [{"id": "sg-1", "ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]}]})
    assert findings[0]["severity"] == "critical"
    assert "administrative port(s) 22" in findings[0]["finding"]


def test_ipv6_admin_port_exposure_is_critical():
    findings = scan_snapshot({"security_groups": [{"id": "sg-ipv6", "ingress": [{"port": 3389, "cidr": "::/0"}]}]})
    assert findings[0]["severity"] == "critical"
    assert "3389" in findings[0]["finding"]


def test_port_range_containing_ssh_is_critical():
    findings = scan_snapshot(
        {
            "security_groups": [
                {
                    "id": "sg-range",
                    "ingress": [{"from_port": 20, "to_port": 25, "cidr": "0.0.0.0/0"}],
                }
            ]
        }
    )
    assert findings[0]["severity"] == "critical"
    assert "22" in findings[0]["finding"]


def test_non_admin_internet_range_is_medium():
    findings = scan_snapshot(
        {
            "security_groups": [
                {
                    "id": "sg-web",
                    "ingress": [{"from_port": 8000, "to_port": 8100, "cidr": "::/0"}],
                }
            ]
        }
    )
    assert findings[0]["severity"] == "medium"
    assert "8000-8100" in findings[0]["finding"]


def test_private_admin_range_does_not_generate_exposure_finding():
    findings = scan_snapshot(
        {
            "security_groups": [
                {
                    "id": "sg-private",
                    "ingress": [{"from_port": 20, "to_port": 25, "cidr": "10.0.0.0/8"}],
                }
            ],
            "account_logging": {"cloudtrail_enabled": True, "log_retention_days": 90},
        }
    )
    assert findings == []


def test_wildcard_iam_policy_is_critical():
    findings = scan_snapshot({"iam_policies": [{"name": "bad", "actions": ["*"], "resources": ["*"]}]})
    assert findings[0]["severity"] == "critical"
    assert "wildcard actions" in findings[0]["finding"]


def test_disabled_logging_generates_finding():
    findings = scan_snapshot({"account_logging": {"cloudtrail_enabled": False, "log_retention_days": 30}})
    assert len(findings) == 2
