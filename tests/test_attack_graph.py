import pytest
import pandas as pd
from attack_graph import build_attack_graph, calculate_blast_radius

def test_build_attack_graph_nodes_and_edges():
    events = pd.DataFrame([
        {
            "event_id": "EV-01",
            "control_id": "CTRL-001",
            "domain": "AWS Cloud",
            "asset_target": "production-db-s3",
            "changed_by": "actor-99",
            "severity": "CRITICAL",
            "timestamp": "2026-10-13 10:00:00",
            "predicted_risky": 1
        },
        {
            "event_id": "EV-02",
            "control_id": "CTRL-010",
            "domain": "Network Firewall",
            "asset_target": "hq-edge-fw",
            "changed_by": "actor-99",
            "severity": "HIGH",
            "timestamp": "2026-10-13 10:05:00",
            "predicted_risky": 1
        }
    ])
    G, stats = build_attack_graph(events)
    assert G.number_of_nodes() >= 4  # actor, controls, domains, assets
    assert G.has_edge("actor-99", "CTRL-001") or G.has_edge("CTRL-001", "production-db-s3")
    assert stats["active_threat_nodes"] > 0
    assert "AWS Cloud" in stats["impacted_domains"]

def test_blast_radius_calculation():
    score, details = calculate_blast_radius(
        num_compromised_controls=4,
        num_domains=3,
        has_critical=True,
        has_production=True
    )
    assert 0 <= score <= 100
    assert score >= 70 # High impact multi-domain critical event
    assert any("CRITICAL" in d for d in details)
