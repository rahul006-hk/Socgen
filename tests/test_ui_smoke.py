import json
import pandas as pd
from attack_graph import build_attack_graph, calculate_blast_radius, get_plotly_network_figure
from remediation import generate_remediation_payload
from copilot import generate_incident_briefing, ask_copilot
from compliance import calculate_framework_posture, export_audit_report

def test_full_pipeline_smoke():
    with open("baseline_controls.json", "r") as f:
        baselines = json.load(f)
    df = pd.read_csv("drift_event_labels.csv")
    
    # 1. Attack graph test (dark and light theme support)
    G, stats = build_attack_graph(df)
    assert stats["active_threat_nodes"] > 0
    fig_dark = get_plotly_network_figure(G, theme="dark")
    assert fig_dark is not None
    assert fig_dark.layout.paper_bgcolor == "#111827"
    fig_light = get_plotly_network_figure(G, theme="light")
    assert fig_light is not None
    assert fig_light.layout.paper_bgcolor == "#ffffff"
    
    # 2. Blast radius test
    score, factors = calculate_blast_radius(5, 3, True, True)
    assert score > 70
    assert len(factors) > 0
    
    # 3. Remediation test
    ctrl = next(iter(baselines.values()))
    payload = generate_remediation_payload(ctrl, "drifted_val")
    assert payload["code_snippet"] != ""
    assert "remediation_type" in payload
    
    # 4. Copilot test
    incident = {
        "incident_name": "Test Incident",
        "domains_implicated": ["AWS Cloud"],
        "controls_compromised": ["CTRL-001"],
        "incident_window_start": "2026-10-13 12:00:00"
    }
    briefing = generate_incident_briefing(incident)
    assert "Executive Summary" in briefing["markdown_report"]
    query_resp = ask_copilot("What are the critical alerts?", {"critical_alerts": 3})
    assert "critical" in query_resp.lower()
    
    # 5. Compliance test
    posture = calculate_framework_posture(df, baselines)
    report = export_audit_report(posture)
    assert "AUDIT" in report

def test_app_clean_typography_no_emojis():
    with open("app.py", "r", encoding="utf-8") as f:
        app_source = f.read()
    
    # Ensure no common emojis remain in headers, titles, or tab labels
    forbidden_emojis = ["🛡️", "🎛️", "📊", "🧩", "🕸️", "⚡", "🤖", "📜", "📋", "🔬", "⏱️", "🚨", "💥", "🫀", "🔗", "🔴"]
    for emoji in forbidden_emojis:
        assert emoji not in app_source, f"Emoji '{emoji}' found in app.py"

