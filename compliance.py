from typing import Dict, Any
import pandas as pd
from datetime import datetime

FRAMEWORKS = ["NIST SP 800-53", "CIS Benchmarks", "GDPR", "PCI-DSS"]

def calculate_framework_posture(df_events: pd.DataFrame, baseline_store: Dict[str, Any], selected_domains: list = None) -> Dict[str, Any]:
    """
    Computes real-time compliance health posture scores across regulatory frameworks
    by mapping active baseline controls and filtering by active unsuppressed drifts.
    Optionally scopes calculation to selected_domains.
    """
    posture = {
        fw: {"total_controls": 0, "passed": 0, "failed": 0, "compliance_rate": 100.0}
        for fw in FRAMEWORKS
    }
    
    risky_cids = set()
    if "predicted_risky" in df_events.columns:
        risky_cids = set(df_events[df_events["predicted_risky"] == 1]["control_id"].unique())

    for cid, rule in baseline_store.items():
        if selected_domains is not None and rule.get("domain") not in selected_domains:
            continue
        mapping = str(rule.get("compliance_mapping", "")).upper()
        for fw in FRAMEWORKS:
            match = False
            if fw == "NIST SP 800-53" and "NIST" in mapping:
                match = True
            elif fw == "CIS Benchmarks" and "CIS" in mapping:
                match = True
            elif fw == "GDPR" and "GDPR" in mapping:
                match = True
            elif fw == "PCI-DSS" and "PCI" in mapping:
                match = True

            if match:
                posture[fw]["total_controls"] += 1
                if cid in risky_cids:
                    posture[fw]["failed"] += 1
                else:
                    posture[fw]["passed"] += 1

    for fw, stats in posture.items():
        if stats["total_controls"] > 0:
            rate = (stats["passed"] / stats["total_controls"]) * 100.0
            stats["compliance_rate"] = round(rate, 1)

    return posture

def export_audit_report(posture: Dict[str, Any]) -> str:
    """
    Synthesizes a formal SOC Compliance Attestation report ready for export.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# SOCGEN DRIFTSHIELD CONTINUOUS COMPLIANCE AUDIT",
        f"**Audit Snapshot Date:** `{timestamp}`  ",
        "**Environment Scope:** Enterprise Multi-Cloud Infrastructure (AWS Cloud, K8s, Perimeter Firewall, Endpoint Security)\n",
        "| Standard / Framework | Evaluated Controls | Passed (Compliant) | Active Drifts (Non-Compliant) | Health Score |",
        "| :--- | :---: | :---: | :---: | :---: |"
    ]
    for fw, stats in posture.items():
        lines.append(f"| **{fw}** | {stats['total_controls']} | {stats['passed']} | {stats['failed']} | **{stats['compliance_rate']}%** |")
    
    lines.append("\n### Compliance Attestation Statement")
    lines.append("All configuration change events were programmatically evaluated against the DriftShield Contextual Engine.")
    lines.append("Authorized CI/CD pipeline deployments and pre-scheduled emergency maintenance windows were validated and suppressed as benign operational noise.")
    return "\n".join(lines)
