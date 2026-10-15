import pandas as pd
import json
import os
from collections import Counter

SEQUENCE_PATTERNS = {
    "impair_defenses": ["impair_defenses", "persistence", "exfiltration"],
    "defense_evasion": ["impair_defenses", "persistence"],
}

def _coerce_bool(value):
    if pd.isna(value):
        return False
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)

def _score_sequence_alerts(df):
    scored = df.copy()
    scored["timestamp"] = pd.to_datetime(scored["timestamp"], errors="coerce")
    scored = scored.sort_values(["changed_by", "timestamp"]).reset_index(drop=True)
    scored["__row_id"] = scored.index
    alerts = []
    
    for actor, actor_events in scored.groupby("changed_by", dropna=False):
        actor_events = actor_events.sort_values("timestamp").reset_index(drop=True)
        if actor_events.empty:
            continue
        for idx in range(len(actor_events)):
            window = actor_events.iloc[max(0, idx - 3): idx + 1].copy()
            categories = [
                str(row.get("sequence_category") or "").strip().lower()
                for _, row in window.iterrows()
                if str(row.get("sequence_category") or "").strip().lower()
            ]
            if not categories:
                continue
            for pattern_name, pattern in SEQUENCE_PATTERNS.items():
                if len(categories) >= len(pattern) and categories[-len(pattern):] == pattern:
                    for offset in range(len(pattern)):
                        if idx - offset >= 0:
                            alerts.append((actor_events.iloc[idx - offset]["__row_id"], pattern_name, len(pattern)))
                    break
                    
    alert_index = set(index for index, _, _ in alerts)
    scored["sequence_alert"] = False
    scored.loc[list(alert_index), "sequence_alert"] = True
    return scored

def analyze_and_predict_drift(filename="drift_event_labels.csv"):
    print("[ENGINE] Running target-aligned engine configuration processing analysis...")
    if not os.path.exists("baseline_controls.json"):
        print("[ERROR] 'baseline_controls.json' is missing! Run generate_data.py first.")
        return None
        
    with open("baseline_controls.json", "r") as f:
        baseline_rules = json.load(f)
        
    df = pd.read_csv(filename)
    df = _score_sequence_alerts(df)
    
    predictions = []
    risk_scores = []
    status_logs = []

    for idx, row in df.iterrows():
        cid = row['control_id']

        telemetry_gap = _coerce_bool(row.get("telemetry_gap", False))
        if telemetry_gap or (str(row.get("new_value", "")) == "stale" and str(row.get("parameter", "")) == "heartbeat_status"):
            if row.get("is_maintenance_window") or row.get("approval_status") == "Approved-Emergency":
                predictions.append(0)
                risk_scores.append(0.0)
                status_logs.append("Suppressed (Telemetry Dropout During Maintenance)")
            else:
                predictions.append(1)
                risk_scores.append(10.4)
                status_logs.append("Heartbeat Alert (Telemetry Gap / Missing Heartbeat)")
            continue

        if cid not in baseline_rules:
            predictions.append(0)
            risk_scores.append(0.0)
            status_logs.append("Normal State")
            continue
            
        rule = baseline_rules[cid]
        observed = row['new_value']
        expected = rule['expected_value']
        
        if str(observed) == str(expected):
            predictions.append(0)
            risk_scores.append(0.0)
            status_logs.append("Normal State")
            continue

        sequence_alert = bool(row.get("sequence_alert", False))

        is_approved = row.get("approval_status") in ("Approved-Pipeline", "Approved-Emergency")
        is_automated_source = row.get("source") in ("CI/CD", "Autoscale")
        is_maintenance = bool(row.get("is_maintenance_window", False))
        is_nonprod = row.get("env") in ("development", "testing", "staging")
        ticket_expired = row.get("ticket_age_days", 0) and row.get("ticket_age_days", 0) > 30

        context_is_benign = (is_approved or is_automated_source) and not ticket_expired

        if sequence_alert:
            predictions.append(1)
            multiplier = 1.5 if rule.get("severity") == "CRITICAL" else 1.2 if rule.get("severity") == "HIGH" else 1.0
            risk_scores.append(rule.get("weight", 8) * multiplier * 1.15)
            status_logs.append(f"Active Alert (Sequence Pattern / {rule.get('severity')} Security Risk)")

        elif rule.get("severity") == "CRITICAL" and not (is_approved or is_automated_source):
            predictions.append(1)
            risk_scores.append(rule.get("weight", 8) * 1.5)
            status_logs.append("Active Alert (Unapproved Critical Control Change)")

        elif context_is_benign:
            predictions.append(0)
            risk_scores.append(0.0)
            if is_maintenance:
                status_logs.append("Suppressed (Authorized Maintenance Window)")
            elif is_automated_source or is_approved:
                status_logs.append("Suppressed (Routine Whitelisted Automation)")
            elif is_nonprod:
                status_logs.append("Suppressed (Non-Production Testing Environment)")
            else:
                status_logs.append("Suppressed (Benign Anomaly Noise)")

        elif rule.get("severity") in ("LOW", "MEDIUM") and not ticket_expired:
            predictions.append(0)
            risk_scores.append(0.0)
            status_logs.append("Suppressed (Low-Severity Ambiguous Change)")

        else:
            predictions.append(1)
            multiplier = 1.5 if rule.get("severity") == "CRITICAL" else 1.2 if rule.get("severity") == "HIGH" else 1.0
            discount = 0.6 if (is_maintenance or is_nonprod) else 1.0
            escalation = 1.3 if ticket_expired else 1.0
            reason = "Overdue Temporary Change" if ticket_expired else rule.get("severity") + " Security Risk"
            risk_scores.append(rule.get("weight", 8) * multiplier * discount * escalation)
            status_logs.append(f"Active Alert ({reason})")

    df['predicted_risky'] = predictions
    df['calculated_risk_score'] = risk_scores
    df['engine_status_summary'] = status_logs
    df.to_csv(filename, index=False)
    print("[OK] Performance metrics optimized successfully.")
    return df

def compute_validation_metrics(df):
    if "ground_truth_label" in df.columns:
        labels = df["ground_truth_label"].astype(str).str.lower()
        predictions = df["predicted_risky"].astype(int)
        truth_binary = labels.isin(["malicious", "true", "1", "risky", "yes"]).astype(int)
    else:
        labels = df["is_risky"].astype(int)
        truth_binary = labels
        predictions = df["predicted_risky"].astype(int)
        
    true_positives = int(((predictions == 1) & (truth_binary == 1)).sum())
    false_positives = int(((predictions == 1) & (truth_binary == 0)).sum())
    false_negatives = int(((predictions == 0) & (truth_binary == 1)).sum())
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }

def run_cross_domain_correlator(df, window_minutes=15):
    print("[ENGINE] Scanning for multi-vector timeline clusters...")
    alerts = df[df["predicted_risky"] == 1].copy()
    if len(alerts) < 2:
        print("[INFO] Insufficient active threat events to correlate.")
        return []
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])
    alerts = alerts.sort_values(by="timestamp")
    compound_incidents = []
    
    for _, current_row in alerts.iterrows():
        window_start = current_row["timestamp"]
        window_end = window_start + pd.Timedelta(minutes=window_minutes)
        matches = alerts[
            (alerts["timestamp"] >= window_start) & 
            (alerts["timestamp"] <= window_end) & 
            (alerts["domain"] != current_row["domain"])
        ]
        if not matches.empty:
            involved_domains = list(set([current_row["domain"]] + list(matches["domain"].unique())))
            involved_controls = list(set([current_row["control_id"]] + list(matches["control_id"].unique())))
            name = "[CRITICAL] Coordinated Multi-Vector Attack Strategy" if "AWS Cloud" in involved_domains and "Network Firewall" in involved_domains else "[HIGH RISK] Cross-Domain Compound Drift Cluster"
            compound_incidents.append({
                "incident_name": name,
                "domains_implicated": involved_domains,
                "controls_compromised": involved_controls,
                "incident_window_start": window_start.strftime("%Y-%m-%d %H:%M:%S")
            })
            
    unique_compounds = {json.dumps(x, sort_keys=True): x for x in compound_incidents}.values()
    print(f"[OK] Found {len(unique_compounds)} unique compound cross-domain incident sequences.\n")
    return list(unique_compounds)

if __name__ == "__main__":
    processed_df = analyze_and_predict_drift()
    compounds = run_cross_domain_correlator(processed_df)