import pytest
from remediation import generate_remediation_payload, RemediationType

def test_generate_terraform_remediation_for_aws():
    control = {
        "control_id": "CTRL-005",
        "domain": "AWS Cloud",
        "asset_target": "production-db-s3",
        "parameter": "s3_bucket_public_access",
        "expected_value": "blocked",
        "severity": "CRITICAL",
        "remediation_steps": "Enforce S3 Block Public Access setting."
    }
    payload = generate_remediation_payload(control, observed_value="public")
    assert payload["control_id"] == "CTRL-005"
    assert payload["remediation_type"] == RemediationType.TERRAFORM
    assert "aws_s3_bucket_public_access_block" in payload["code_snippet"]
    assert "block_public_acls = true" in payload["code_snippet"]
    assert payload["rollback_diff"] != ""

def test_generate_k8s_remediation():
    control = {
        "control_id": "CTRL-020",
        "domain": "Kubernetes",
        "asset_target": "prod-core-cluster",
        "parameter": "allow_privileged_containers",
        "expected_value": "false",
        "severity": "CRITICAL",
        "remediation_steps": "Deny privileged containers."
    }
    payload = generate_remediation_payload(control, observed_value="true")
    assert payload["remediation_type"] == RemediationType.KUBERNETES
    assert "securityContext" in payload["code_snippet"]
    assert "privileged: false" in payload["code_snippet"]

def test_generate_firewall_cli_remediation():
    control = {
        "control_id": "CTRL-015",
        "domain": "Network Firewall",
        "asset_target": "hq-edge-fw",
        "parameter": "port_8080_ingress",
        "expected_value": "blocked",
        "severity": "HIGH",
        "remediation_steps": "Close port 8080."
    }
    payload = generate_remediation_payload(control, observed_value="open")
    assert payload["remediation_type"] == RemediationType.CLI
    assert "iptables" in payload["code_snippet"] or "ufw" in payload["code_snippet"]
