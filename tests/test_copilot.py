import pytest
from copilot import generate_incident_briefing, ask_copilot

def test_generate_incident_briefing():
    incident = {
        "incident_name": "[CRITICAL] Coordinated Multi-Vector Attack Strategy",
        "domains_implicated": ["AWS Cloud", "Network Firewall"],
        "controls_compromised": ["CTRL-001", "CTRL-005", "CTRL-015"],
        "incident_window_start": "2026-10-13 14:00:00"
    }
    briefing = generate_incident_briefing(incident)
    assert briefing["title"] != ""
    assert "Executive Summary" in briefing["markdown_report"]
    assert "MITRE Tactic Mapping" in briefing["markdown_report"]
    assert "Recommended Actions" in briefing["markdown_report"]

def test_ask_copilot_query():
    context = {"total_drifts": 120, "critical_alerts": 8, "high_alerts": 14}
    response = ask_copilot("How many critical alerts are active and what should I triage first?", context)
    assert "8 critical" in response.lower() or "critical" in response.lower()
    assert "triage" in response.lower() or "immediate" in response.lower() or "priority" in response.lower()
