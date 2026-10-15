import pytest
import pandas as pd
from compliance import calculate_framework_posture, export_audit_report

def test_calculate_framework_posture():
    df = pd.DataFrame([
        {"control_id": "CTRL-001", "predicted_risky": 0},
        {"control_id": "CTRL-002", "predicted_risky": 1},
        {"control_id": "CTRL-003", "predicted_risky": 0},
    ])
    baseline_store = {
        "CTRL-001": {"compliance_mapping": "NIST SP 800-53 (IA-2)", "domain": "AWS Cloud"},
        "CTRL-002": {"compliance_mapping": "CIS AWS 1.1, GDPR Art 32", "domain": "AWS Cloud"},
        "CTRL-003": {"compliance_mapping": "PCI-DSS 3.4", "domain": "Cloud Database"}
    }
    posture = calculate_framework_posture(df, baseline_store)
    assert "NIST SP 800-53" in posture
    assert "CIS Benchmarks" in posture
    assert posture["NIST SP 800-53"]["compliance_rate"] == 100.0
    assert posture["CIS Benchmarks"]["compliance_rate"] < 100.0

    # Test filtering to specific domain
    posture_filtered = calculate_framework_posture(df, baseline_store, selected_domains=["Cloud Database"])
    assert posture_filtered["NIST SP 800-53"]["total_controls"] == 0
    assert posture_filtered["PCI-DSS"]["total_controls"] == 1
    assert posture_filtered["PCI-DSS"]["compliance_rate"] == 100.0

def test_export_audit_report():
    posture = {
        "NIST SP 800-53": {"total_controls": 10, "passed": 9, "failed": 1, "compliance_rate": 90.0}
    }
    report_md = export_audit_report(posture)
    assert "# SOCGEN DRIFTSHIELD CONTINUOUS COMPLIANCE AUDIT" in report_md
    assert "90.0%" in report_md
