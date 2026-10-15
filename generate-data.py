import pandas as pd
import random
import json
from datetime import datetime, timedelta

DOMAINS = {
    "AWS Cloud": {
        "parameters": [
            ("root_account_mfa", "enabled", "disabled", "CRITICAL", "NIST SP 800-53 (IA-2)", "Enable MFA via AWS IAM Console.", "T1556 - Modify Authentication Process"),
            ("s3_bucket_public_access", "blocked", "public", "CRITICAL", "CIS AWS 1.1, GDPR Art 32", "Enforce S3 Block Public Access setting.", "T1530 - Data from Cloud Storage Object"),
            ("cloudtrail_logging", "enabled", "disabled", "HIGH", "NIST SP 800-53 (SI-4)", "Re-enable CloudTrail via Terraform.", "T1562.008 - Impair Defenses: Disable Cloud Logs"),
            ("kms_key_rotation", "enabled", "disabled", "MEDIUM", "CIS AWS 2.8", "Enable annual rotation on customer managed keys.", "T1600.001 - Weaken Encryption: Reduce Key Space")
        ],
        "assets": ["production-db-s3", "user-vault-s3", "app-logs-s3", "billing-data-s3"]
    },
    "Network Firewall": {
        "parameters": [
            ("port_8080_ingress", "blocked", "open", "HIGH", "CIS Firewall Benchmark 1.2", "Close public port 8080 ingress; route via VPN.", "T1133 - External Remote Services"),
            ("ssh_port_22_ingress", "blocked", "open", "CRITICAL", "NIST SP 800-53 (AC-17)", "Restrict port 22 access to secure jumpbox IPs.", "T1133 - External Remote Services"),
            ("outbound_data_leaks", "restricted", "unrestricted", "HIGH", "GDPR Art 25", "Re-apply egress filtering rules on firewall appliance.", "T1048 - Exfiltration Over Alternative Protocol"),
            ("timeout_period", "600", "86400", "LOW", "CIS Benchmark 4.1", "Revert session timeout durations back to 10 minutes.", "T1078 - Valid Accounts")
        ],
        "assets": ["hq-edge-fw", "dublin-dc-switch", "tokyo-office-router", "dmz-firewall"]
    },
    "Kubernetes": {
        "parameters": [
            ("allow_privileged_containers", "false", "true", "CRITICAL", "CIS Kubernetes 5.2.1", "Update PodSecurityPolicy to deny privileged pods.", "T1611 - Escape to Host"),
            ("network_policy_default_deny", "true", "false", "HIGH", "CIS Kubernetes 5.1.4", "Apply default-deny ingress network isolation manifest.", "T1599 - Network Boundary Bridging"),
            ("dashboard_exposed", "false", "true", "HIGH", "NIST SP 800-53 (SC-7)", "Disable public access route to K8s dashboard dashboard.", "T1133 - External Remote Services"),
            ("image_pull_policy", "Always", "IfNotPresent", "LOW", "CIS Kubernetes 4.2", "Reset container deployment pull policy configuration.", "T1036 - Masquerading")
        ],
        "assets": ["prod-core-cluster", "staging-mesh", "payment-gateway-k8s", "auth-service-nodes"]
    },
    "Endpoint Security": {
        "parameters": [
            ("agent_status", "running", "installed-not-running", "HIGH", "NIST SP 800-53 (CM-2)", "Restart the endpoint agent service daemon via orchestration.", "T1562.001 - Impair Defenses: Disable or Modify Tools"),
            ("edr_realtime_scan", "enabled", "disabled", "CRITICAL", "NIST SP 800-53 (SI-3)", "Re-enable real-time file behavioral scanning protection.", "T1562.001 - Impair Defenses: Disable or Modify Tools"),
            ("usb_mass_storage", "blocked", "allowed", "MEDIUM", "GDPR Art 32", "Re-apply corporate endpoint group policy asset block.", "T1052.001 - Exfiltration Over Physical Medium: USB"),
            ("definition_age_days", "0", "15", "LOW", "CIS Endpoint 2.1", "Force immediate update of local anti-malware definition signatures.", "T1562.001 - Impair Defenses: Disable or Modify Tools")
        ],
        "assets": ["finance-dept-vdi", "domain-controller-01", "payroll-server-win", "exec-laptop-fleet"]
    }
}

def generate_enterprise_datasets():
    base_time = datetime.now()
    
    baseline_store = {}
    control_metadata = []
    
    control_counter = 1
    for domain_name, data in DOMAINS.items():
        for param, expected, _, severity, compliance, remediation, mitre_technique in data["parameters"]:
            for asset in data["assets"]:
                control_id = f"CTRL-{control_counter:03d}"
                
                control_entry = {
                    "control_id": control_id,
                    "domain": domain_name,
                    "asset_target": asset,
                    "parameter": param,
                    "expected_value": expected,
                    "severity": severity,
                    "weight": 10 if severity == "CRITICAL" else (8 if severity == "HIGH" else (5 if severity == "MEDIUM" else 2)),
                    "compliance_mapping": compliance,
                    "remediation_steps": remediation,
                    "mitre_technique": mitre_technique
                }
                
                baseline_store[control_id] = control_entry
                control_metadata.append(control_entry)
                control_counter += 1
                
    with open("baseline_controls.json", "w") as f:
        json.dump(baseline_store, f, indent=2)
    pd.DataFrame(control_metadata).to_csv("control_metadata.csv", index=False)
    print(f"✅ Generated {len(control_metadata)} Baseline Control Matrix Entries.")

    maint_windows = []
    for w in range(35): # 35 discrete windows
        start_win = base_time - timedelta(minutes=random.randint(10, 2000))
        maint_windows.append({
            "window_id": f"WIN-{100 + w}",
            "start_time": start_win.isoformat(),
            "end_time": (start_win + timedelta(hours=2)).isoformat(),
            "approved_scope_domain": random.choice(list(DOMAINS.keys()))
        })
    df_maint = pd.DataFrame(maint_windows)
    df_maint.to_csv("maintenance_windows.csv", index=False)
    print(f"✅ Generated {len(df_maint)} Corporate Maintenance Window Blocks.")

    events = []
    control_ids_list = list(baseline_store.keys())
    
    for i in range(1000): # Exactly 1,000 records
        control_id = random.choice(control_ids_list)
        rule = baseline_store[control_id]
        
        param_options = [p for p in DOMAINS[rule["domain"]]["parameters"] if p[0] == rule["parameter"]][0]
        drifted_value = param_options[2]
        
        timestamp = (base_time - timedelta(minutes=i * 2.5))
        
        old_value = rule["expected_value"]
        new_value = rule["expected_value"]
        source = "manual"
        approval_status = "Unapproved"
        is_maintenance_window = False
        env = random.choices(["production", "staging", "development"], weights=[0.6, 0.3, 0.1])[0]
        ticket_age_days = 0
        is_risky = False
        telemetry_gap = False
        sequence_category = None
        
        overlapping_wins = df_maint[
            (pd.to_datetime(df_maint["start_time"]) <= timestamp) & 
            (pd.to_datetime(df_maint["end_time"]) >= timestamp) & 
            (df_maint["approved_scope_domain"] == rule["domain"])
        ]
        if not overlapping_wins.empty:
            is_maintenance_window = True
            
        roll = random.random()
        
        if roll < 0.50:  # Benign Operations
            new_value = drifted_value
            source = random.choice(["CI/CD", "Autoscale"])
            approval_status = "Approved-Pipeline"
            is_risky = False
        elif roll < 0.70:  # Normal State Verification
            is_risky = False
        elif roll < 0.85:  # Confirmed Security Risks
            new_value = drifted_value
            is_risky = True
            if rule["severity"] == "CRITICAL" and env == "production":
                source = "manual"  # Direct violation of Case 1/Case 2 parameters
            elif rule["parameter"] == "port_8080_ingress":
                ticket_age_days = random.randint(30, 365) # Expired Ticket case
        else:  # Ambiguous Context Conditions
            new_value = drifted_value
            if env in ["development", "testing"]:
                is_risky = False # Non-production adjustments are safe
            elif is_maintenance_window:
                approval_status = "Approved-Emergency"
                is_risky = False

        if is_risky:
            ground_truth_label = "malicious"
        elif is_maintenance_window or approval_status in {"Approved-Emergency", "Approved-Pipeline"} or source in {"CI/CD", "Autoscale"}:
            ground_truth_label = "benign"
        else:
            ground_truth_label = "ambiguous"

        events.append({
            "event_id": f"EV-{5000 + i}",
            "control_id": control_id,
            "domain": rule["domain"],
            "asset_target": rule["asset_target"],
            "parameter": rule["parameter"],
            "old_value": old_value,
            "new_value": new_value,
            "severity": rule["severity"],
            "changed_by": f"actor-{random.randint(50, 500)}",
            "timestamp": timestamp.isoformat(),
            "source": source,
            "approval_status": approval_status,
            "is_maintenance_window": is_maintenance_window,
            "ticket_age_days": ticket_age_days,
            "env": env,
            "is_risky": is_risky,
            "telemetry_gap": telemetry_gap,
            "sequence_category": sequence_category,
            "ground_truth_label": ground_truth_label,
        })

    _ct_id  = next(cid for cid, r in baseline_store.items() if r["parameter"] == "cloudtrail_logging")
    _mfa_id = next(cid for cid, r in baseline_store.items() if r["parameter"] == "root_account_mfa")
    _fw_id  = next(cid for cid, r in baseline_store.items() if r["parameter"] == "port_8080_ingress")
    _ep_id  = next(cid for cid, r in baseline_store.items() if r["parameter"] == "agent_status")
    _k8_id  = next(cid for cid, r in baseline_store.items() if r["parameter"] == "allow_privileged_containers")
    _edr_id = next(cid for cid, r in baseline_store.items() if r["parameter"] == "edr_realtime_scan")

    seq_a_base = base_time - timedelta(hours=3)   # explicit anchor time
    for step, (cid, domain, param, val, cat, mins) in enumerate([
        (_ct_id,  "AWS Cloud",         "cloudtrail_logging", "disabled",              "impair_defenses", 0),
        (_mfa_id, "AWS Cloud",         "root_account_mfa",   "disabled",              "persistence",     3),
    ]):
        r = baseline_store[cid]
        events.append({
            "event_id":              f"EV-SEQA-{step+1:02d}",
            "control_id":            cid,
            "domain":                domain,
            "asset_target":          r["asset_target"],
            "parameter":             param,
            "old_value":             r["expected_value"],
            "new_value":             val,
            "severity":              r["severity"],
            "changed_by":            "actor-attack-seq",
            "timestamp":             (seq_a_base + timedelta(minutes=mins)).isoformat(),
            "source":                "manual",
            "approval_status":       "Unapproved",
            "is_maintenance_window": False,
            "ticket_age_days":       0,
            "env":                   "production",
            "is_risky":              True,
            "telemetry_gap":         False,
            "sequence_category":     cat,
            "ground_truth_label":    "malicious",
        })

    seq_b_base = base_time - timedelta(hours=5)
    for step, (cid, domain, param, val, cat, mins) in enumerate([
        (_fw_id,  "Network Firewall",  "port_8080_ingress",  "open",                  "impair_defenses", 0),
        (_ep_id,  "Endpoint Security", "agent_status",        "installed-not-running", "persistence",     3),
        (_edr_id, "Endpoint Security", "edr_realtime_scan",   "disabled",              "exfiltration",    6),
    ]):
        r = baseline_store[cid]
        events.append({
            "event_id":              f"EV-SEQB-{step+1:02d}",
            "control_id":            cid,
            "domain":                domain,
            "asset_target":          r["asset_target"],
            "parameter":             param,
            "old_value":             r["expected_value"],
            "new_value":             val,
            "severity":              r["severity"],
            "changed_by":            "actor-attack-seq-2",
            "timestamp":             (seq_b_base + timedelta(minutes=mins)).isoformat(),
            "source":                "manual",
            "approval_status":       "Unapproved",
            "is_maintenance_window": False,
            "ticket_age_days":       45 if param == "port_8080_ingress" else 0,
            "env":                   "production",
            "is_risky":              True,
            "telemetry_gap":         False,
            "sequence_category":     cat,
            "ground_truth_label":    "malicious",
        })

    gap_control = next(control_id for control_id, rule in baseline_store.items() if rule["parameter"] == "agent_status")
    gap_endpoints = ["finance-dept-vdi", "domain-controller-01", "payroll-server-win", "exec-laptop-fleet", "prod-core-cluster"]
    gap_actors    = ["actor-telemetry-gap-1", "actor-telemetry-gap-2", "actor-telemetry-gap-3", "actor-telemetry-gap-4", "actor-telemetry-gap-5"]

    for gap_i, (actor, endpoint) in enumerate(zip(gap_actors, gap_endpoints)):
        gap_time = base_time - timedelta(hours=2 + gap_i * 6)   # spread 6h apart
        events.append({
            "event_id":             f"EV-GAP-{gap_i+1:02d}",
            "control_id":           gap_control,
            "domain":               "Endpoint Security",
            "asset_target":         endpoint,
            "parameter":            "heartbeat_status",
            "old_value":            "active",
            "new_value":            "stale",
            "severity":             "HIGH",
            "changed_by":           actor,
            "timestamp":            gap_time.isoformat(),
            "source":               "telemetry-monitor",
            "approval_status":      "Unapproved",
            "is_maintenance_window": False,
            "ticket_age_days":      0,
            "env":                  "production",
            "is_risky":             True,
            "telemetry_gap":        True,
            "sequence_category":    None,
            "ground_truth_label":   "malicious",
        })

    df_events = pd.DataFrame(events)
    df_events.to_csv("drift_event_labels.csv", index=False)

    eval_subset = df_events.sample(n=min(250, len(df_events)), random_state=42)[["event_id", "ground_truth_label"]]
    eval_subset.to_csv("eval_labels.csv", index=False)
    print(f"✅ Generated {len(df_events)} Robust Change Event Log Items.")

if __name__ == "__main__":
    generate_enterprise_datasets()