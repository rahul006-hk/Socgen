from enum import Enum
from typing import Dict, Any

class RemediationType(str, Enum):
    TERRAFORM = "Terraform HCL"
    KUBERNETES = "Kubernetes Manifest"
    CLI = "CLI / Shell Script"
    PYTHON = "Boto3 / Python SDK"

def generate_remediation_payload(control: Dict[str, Any], observed_value: Any) -> Dict[str, Any]:
    """
    Synthesizes actionable SOAR remediation playbooks including IaC (Terraform),
    Kubernetes manifests, and CLI scripts with git diff previews for any drifted control.
    """
    domain = control.get("domain", "")
    param = control.get("parameter", "")
    asset = control.get("asset_target", "asset")
    expected = control.get("expected_value", "")
    cid = control.get("control_id", "CTRL-UNKNOWN")
    
    code_snippet = ""
    remediation_type = RemediationType.CLI
    rollback_diff = f"- parameter: {param} = {observed_value}\n+ parameter: {param} = {expected}"
    
    if domain == "AWS Cloud":
        if "s3" in param or "s3" in asset or "bucket" in param:
            remediation_type = RemediationType.TERRAFORM
            code_snippet = (
                f'# Terraform Remediation for {asset}\n'
                f'resource "aws_s3_bucket_public_access_block" "{asset.replace("-", "_")}" {{\n'
                f'  bucket = "{asset}"\n\n'
                f'  block_public_acls = true\n'
                f'  block_public_policy = true\n'
                f'  ignore_public_acls = true\n'
                f'  restrict_public_buckets = true\n'
                f'}}'
            )
        elif "cloudtrail" in param:
            remediation_type = RemediationType.TERRAFORM
            code_snippet = (
                f'# Enforce CloudTrail Logging on {asset}\n'
                f'resource "aws_cloudtrail" "audit_trail" {{\n'
                f'  name                          = "{asset}-trail"\n'
                f'  s3_bucket_name                = "socgen-audit-logs-bucket"\n'
                f'  enable_logging                = true\n'
                f'  include_global_service_events = true\n'
                f'}}'
            )
        elif "mfa" in param:
            remediation_type = RemediationType.CLI
            code_snippet = (
                f'# Enforce Virtual MFA & IAM Password Policy\n'
                f'aws iam update-account-password-policy \\\n'
                f'  --require-symbols \\\n'
                f'  --require-numbers \\\n'
                f'  --minimum-password-length 14 \\\n'
                f'  --require-mfa'
            )
        elif "kms" in param or "rotation" in param:
            remediation_type = RemediationType.TERRAFORM
            code_snippet = (
                f'resource "aws_kms_key" "master_key" {{\n'
                f'  description             = "CMK for {asset}"\n'
                f'  enable_key_rotation     = true\n'
                f'  deletion_window_in_days = 30\n'
                f'}}'
            )
        else:
            remediation_type = RemediationType.CLI
            code_snippet = f'aws configservice start-configuration-recorder --configuration-recorder-name {asset}'

    elif domain == "Kubernetes":
        remediation_type = RemediationType.KUBERNETES
        if "privileged" in param:
            code_snippet = (
                f'# Patch PodSecurityContext for {asset}\n'
                f'apiVersion: apps/v1\n'
                f'kind: Deployment\n'
                f'metadata:\n'
                f'  name: {asset}\n'
                f'spec:\n'
                f'  template:\n'
                f'    spec:\n'
                f'      containers:\n'
                f'      - name: main\n'
                f'        securityContext:\n'
                f'          allowPrivilegeEscalation: false\n'
                f'          privileged: false\n'
                f'          readOnlyRootFilesystem: true'
            )
        elif "network_policy" in param:
            code_snippet = (
                f'# Enforce Default Deny Ingress NetworkPolicy\n'
                f'apiVersion: networking.k8s.io/v1\n'
                f'kind: NetworkPolicy\n'
                f'metadata:\n'
                f'  name: default-deny-ingress\n'
                f'  namespace: default\n'
                f'spec:\n'
                f'  podSelector: {{}}\n'
                f'  policyTypes:\n'
                f'  - Ingress'
            )
        elif "dashboard" in param:
            code_snippet = f'kubectl patch svc kubernetes-dashboard -n kubernetes-dashboard -p \'{{"spec":{{"type":"ClusterIP"}}}}\''
        else:
            code_snippet = f'kubectl set image deployment/{asset} {asset}=secure-image:latest --record'

    elif domain == "Network Firewall":
        remediation_type = RemediationType.CLI
        if "8080" in param:
            code_snippet = (
                f'# Block Public Ingress on Port 8080 and enforce internal VPN gateway\n'
                f'iptables -D INPUT -p tcp --dport 8080 -j ACCEPT\n'
                f'iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT\n'
                f'iptables -A INPUT -p tcp --dport 8080 -j DROP'
            )
        elif "22" in param or "ssh" in param:
            code_snippet = (
                f'# Restrict SSH port 22 access exclusively to corporate jumpbox\n'
                f'iptables -D INPUT -p tcp --dport 22 -j ACCEPT\n'
                f'iptables -A INPUT -p tcp --dport 22 -s 10.10.50.0/24 -j ACCEPT\n'
                f'iptables -A INPUT -p tcp --dport 22 -j DROP'
            )
        elif "leaks" in param or "egress" in param:
            code_snippet = (
                f'# Re-apply strict egress filtering\n'
                f'iptables -P FORWARD DROP\n'
                f'iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
            )
        else:
            code_snippet = f'iptables -A INPUT -m limit --limit 25/minute --limit-burst 100 -j ACCEPT'

    else: # Endpoint Security
        remediation_type = RemediationType.CLI
        if "agent" in param or "edr" in param:
            code_snippet = (
                f'# Restart and re-enable EDR Sensor Daemon on {asset}\n'
                f'systemctl restart edr-sensor-daemon\n'
                f'systemctl enable edr-sensor-daemon\n'
                f'systemctl status edr-sensor-daemon --no-pager'
            )
        elif "usb" in param:
            code_snippet = (
                f'# Enforce Mass Storage Block via Group Policy / Registry\n'
                f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f'
            )
        else:
            code_snippet = f'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature"'

    return {
        "control_id": cid,
        "asset": asset,
        "domain": domain,
        "parameter": param,
        "expected_value": expected,
        "observed_value": observed_value,
        "remediation_type": remediation_type,
        "remediation_summary": control.get("remediation_steps", "Restore baseline configuration."),
        "code_snippet": code_snippet,
        "rollback_diff": rollback_diff
    }
