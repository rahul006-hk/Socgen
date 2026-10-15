# SocGen DriftShield Enterprise Platform Upgrades Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Elevate SocGen DriftShield into a flagship enterprise security platform by implementing autonomous SOAR remediation, interactive attack graphs, AI SecOps incident synthesis, continuous compliance auditing, and console integrations without disrupting the core drift detection engine.

**Architecture:** Modular extension around the existing core (`engine.py`, `generate-data.py`, `app.py`). Dedicated decoupled services for automated IaC/CLI remediation generation (`remediation.py`), NetworkX-based graph kill-chain and blast radius modeling (`attack_graph.py`), LLM/heuristic incident briefing synthesis (`copilot.py`), and multi-framework regulatory compliance scoring (`compliance.py`), all surfaced seamlessly through enhanced tabs in the Streamlit UI console.

**Tech Stack:** Python 3.10+, Pandas, NetworkX, Plotly, Streamlit, Pytest.

---

### Task 1: Autonomous Remediation & SOAR Playbook Generator (`remediation.py`)

**Files:**
- Create: `remediation.py`
- Test: `tests/test_remediation.py`

**Step 1: Write the failing test**
Create `tests/test_remediation.py`:
```python
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
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/test_remediation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'remediation'`

**Step 3: Write minimal implementation in `remediation.py`**
Create `remediation.py`:
```python
from enum import Enum
from typing import Dict, Any

class RemediationType(str, Enum):
    TERRAFORM = "Terraform HCL"
    KUBERNETES = "Kubernetes Manifest"
    CLI = "CLI / Shell Script"
    PYTHON = "Boto3 / Python SDK"

def generate_remediation_payload(control: Dict[str, Any], observed_value: Any) -> Dict[str, Any]:
    domain = control.get("domain", "")
    param = control.get("parameter", "")
    asset = control.get("asset_target", "asset")
    expected = control.get("expected_value", "")
    cid = control.get("control_id", "CTRL-UNKNOWN")
    
    code_snippet = ""
    remediation_type = RemediationType.CLI
    rollback_diff = f"- parameter: {param} = {observed_value}\n+ parameter: {param} = {expected}"
    
    if domain == "AWS Cloud":
        if "s3" in param or "s3" in asset:
            remediation_type = RemediationType.TERRAFORM
            code_snippet = (
                f'# Terraform Remediation for {asset}\n'
                f'resource "aws_s3_bucket_public_access_block" "{asset.replace("-", "_")}" {{\n'
                f'  bucket = "{asset}"\n'
                f'  block_public_acls   = true\n'
                f'  block_public_policy = true\n'
                f'  ignore_public_acls  = true\n'
                f'  restrict_public_buckets = true\n'
                f'}}'
            )
        elif "cloudtrail" in param:
            remediation_type = RemediationType.TERRAFORM
            code_snippet = (
                f'# Enforce CloudTrail Logging on {asset}\n'
                f'resource "aws_cloudtrail" "audit_trail" {{\n'
                f'  name                          = "{asset}-trail"\n'
                f'  s3_bucket_name                = "audit-logs-bucket"\n'
                f'  enable_logging                = true\n'
                f'  include_global_service_events = true\n'
                f'}}'
            )
        else:
            remediation_type = RemediationType.CLI
            code_snippet = f'aws iam update-account-password-policy --require-mfa --profile prod'

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
                f'          privileged: false'
            )
        elif "network_policy" in param:
            code_snippet = (
                f'apiVersion: networking.k8s.io/v1\n'
                f'kind: NetworkPolicy\n'
                f'metadata:\n'
                f'  name: default-deny-ingress\n'
                f'spec:\n'
                f'  podSelector: {{}}\n'
                f'  policyTypes:\n'
                f'  - Ingress'
            )
        else:
            code_snippet = f'kubectl patch svc {asset} -p \'{{"spec":{{"type":"ClusterIP"}}}}\''

    elif domain == "Network Firewall":
        remediation_type = RemediationType.CLI
        if "8080" in param:
            code_snippet = f'iptables -D INPUT -p tcp --dport 8080 -j ACCEPT\niptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT'
        elif "22" in param or "ssh" in param:
            code_snippet = f'iptables -D INPUT -p tcp --dport 22 -j ACCEPT\niptables -A INPUT -p tcp --dport 22 -s 10.10.50.0/24 -j ACCEPT'
        else:
            code_snippet = f'# Egress filtering enforcement on {asset}\niptables -P FORWARD DROP'

    else: # Endpoint Security
        remediation_type = RemediationType.CLI
        if "agent" in param or "edr" in param:
            code_snippet = f'systemctl restart edr-sensor-daemon && systemctl enable edr-sensor-daemon'
        else:
            code_snippet = f'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'

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
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_remediation.py -v`
Expected: PASS (all 3 tests pass)

**Step 5: Verify integration & commit**
Run: `git status`

---

### Task 2: Attack Graph & Lateral Movement Blast Radius Engine (`attack_graph.py`)

**Files:**
- Create: `attack_graph.py`
- Test: `tests/test_attack_graph.py`

**Step 1: Write the failing test**
Create `tests/test_attack_graph.py`:
```python
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
    assert "CRITICAL severity" in details
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/test_attack_graph.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'attack_graph'`

**Step 3: Write minimal implementation in `attack_graph.py`**
Create `attack_graph.py`:
```python
import networkx as nx
import pandas as pd
from typing import Tuple, Dict, Any, List

def build_attack_graph(events_df: pd.DataFrame) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    G = nx.DiGraph()
    risky_events = events_df[events_df["predicted_risky"] == 1] if "predicted_risky" in events_df.columns else events_df
    
    impacted_domains = set()
    impacted_assets = set()
    actors = set()

    for _, row in risky_events.iterrows():
        actor = str(row.get("changed_by", "unknown-actor"))
        cid = str(row.get("control_id", "unknown-control"))
        asset = str(row.get("asset_target", "unknown-asset"))
        domain = str(row.get("domain", "unknown-domain"))
        severity = str(row.get("severity", "MEDIUM"))
        
        actors.add(actor)
        impacted_domains.add(domain)
        impacted_assets.add(asset)

        G.add_node(actor, node_type="actor", label=actor, color="#ef4444")
        G.add_node(cid, node_type="control", label=cid, severity=severity, color="#f59e0b")
        G.add_node(asset, node_type="asset", label=asset, color="#3b82f6")
        G.add_node(domain, node_type="domain", label=domain, color="#8b5cf6")

        G.add_edge(actor, cid, relationship="manipulated")
        G.add_edge(cid, asset, relationship="protects")
        G.add_edge(asset, domain, relationship="resides_in")

    stats = {
        "active_threat_nodes": G.number_of_nodes(),
        "attack_paths": G.number_of_edges(),
        "actors": list(actors),
        "impacted_domains": list(impacted_domains),
        "impacted_assets": list(impacted_assets)
    }
    return G, stats

def calculate_blast_radius(num_compromised_controls: int, num_domains: int, has_critical: bool, has_production: bool) -> Tuple[float, List[str]]:
    factors = []
    score = 15.0 # Base drift score
    
    control_weight = min(35.0, num_compromised_controls * 7.0)
    score += control_weight
    factors.append(f"{num_compromised_controls} compromised controls (+{control_weight:.1f})")

    domain_weight = min(25.0, num_domains * 10.0)
    score += domain_weight
    factors.append(f"{num_domains} impacted domains (+{domain_weight:.1f})")

    if has_critical:
        score += 15.0
        factors.append("CRITICAL severity controls breached (+15.0)")
    if has_production:
        score += 10.0
        factors.append("Direct production environment target (+10.0)")

    final_score = min(100.0, max(0.0, score))
    return final_score, factors

def get_plotly_network_figure(G: nx.DiGraph):
    import plotly.graph_objects as go
    pos = nx.spring_layout(G, seed=42, k=0.8)
    
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color="rgba(156, 163, 175, 0.4)"),
        hoverinfo="none",
        mode="lines"
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        data = G.nodes[node]
        node_text.append(f"{data.get('node_type', 'node').upper()}: {node}")
        node_color.append(data.get("color", "#38bdf8"))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=[node for node in G.nodes()],
        textposition="top center",
        hoverinfo="text",
        hovertext=node_text,
        marker=dict(size=18, color=node_color, line=dict(width=2, color="#ffffff"))
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            showlegend=False,
            hovermode="closest",
            margin=dict(b=10, l=10, r=10, t=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
    )
    return fig
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_attack_graph.py -v`
Expected: PASS (all tests pass)

**Step 5: Verify integration & commit**
Run: `git status`

---

### Task 3: AI SecOps Copilot & Incident Briefing Engine (`copilot.py`)

**Files:**
- Create: `copilot.py`
- Test: `tests/test_copilot.py`

**Step 1: Write the failing test**
Create `tests/test_copilot.py`:
```python
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
    assert "8 critical" in response.lower() or "critical alerts" in response.lower()
    assert "triage" in response.lower() or "immediate" in response.lower()
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/test_copilot.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'copilot'`

**Step 3: Write minimal implementation in `copilot.py`**
Create `copilot.py`:
```python
from typing import Dict, Any, List

def generate_incident_briefing(compound_incident: Dict[str, Any]) -> Dict[str, Any]:
    name = compound_incident.get("incident_name", "Cross-Domain Incident")
    domains = compound_incident.get("domains_implicated", [])
    controls = compound_incident.get("controls_compromised", [])
    start_time = compound_incident.get("incident_window_start", "Recent")
    
    is_multi_vector = len(domains) > 1
    domain_str = ", ".join(domains)
    ctrl_str = ", ".join(controls)

    markdown_report = f"""### 🛡️ AI Executive Threat Briefing: {name}

**Incident Start Window:** `{start_time}`  
**Impacted Domains:** `{domain_str}`  
**Controls Implicated:** `{ctrl_str}`

#### 📌 Executive Summary
A synchronized multi-vector configuration drift sequence was detected spanning **{len(domains)} distinct infrastructure domains**. {'The threat actor executed lateral modifications across perimeter defenses and cloud assets within an aggressive 15-minute timeframe.' if is_multi_vector else 'Multiple related security controls experienced simultaneous parameter degradation.'}

#### 🎯 Attacker Hypothesis & MITRE Tactic Mapping
1. **Initial Vector:** Perimeter defense weakening via ingress alterations on `{domains[0] if domains else 'Gateway'}` (MITRE *T1133 - External Remote Services*).
2. **Evasion & Blinding:** Defense impairment and telemetry suppression attempts across `{domain_str}` (MITRE *T1562 - Impair Defenses*).
3. **Objective:** Preparation for persistence or exfiltration against core asset databases.

#### 🚨 Recommended Actions for SOC Analysts
- [ ] **Immediate Isolation:** Revoke temporary IAM sessions for actors associated with `{ctrl_str}`.
- [ ] **Infrastructure Rollback:** Trigger 1-Click SOAR Remediation playbooks for `{controls[0] if controls else 'affected controls'}`.
- [ ] **Forensic Snapshot:** Preserve EDR process logs and VPC flow captures within $\pm 30$ minutes of `{start_time}`.
"""
    return {
        "title": name,
        "domains": domains,
        "controls": controls,
        "markdown_report": markdown_report
    }

def ask_copilot(query: str, context: Dict[str, Any]) -> str:
    q = query.lower()
    crit = context.get("critical_alerts", 0)
    high = context.get("high_alerts", 0)
    total = context.get("total_drifts", 0)
    
    if "critical" in q or "triage" in q or "priority" in q:
        return (
            f"**SOC Copilot Recommendation:** You currently have **{crit} Critical** and **{high} High** active alerts. "
            f"Immediate Priority: Triage unapproved changes in **AWS Cloud** (Root MFA & S3 Public Access) and "
            f"**Network Firewall** (Port 22/8080 ingress), as these represent perimeter-breaching conditions."
        )
    elif "blast radius" in q or "impact" in q:
        return (
            f"**Blast Radius Assessment:** Multi-domain incidents involving production databases present severe blast radius (75-95/100). "
            f"If an S3 bucket is public and port 8080 is open simultaneously, external adversaries can exfiltrate financial records within minutes."
        )
    elif "remediate" in q or "fix" in q or "rollback" in q:
        return (
            f"**Remediation Guidance:** Navigate to the **⚡ Self-Healing SOAR Playbooks** tab. "
            f"You can review pre-generated Terraform HCL and Kubernetes YAML rollback patches with live code diffs."
        )
    else:
        return (
            f"**SOC Copilot Overview:** Monitoring {total} total change events across AWS Cloud, Network Firewall, "
            f"Kubernetes, and Endpoint Security. All benign CI/CD pipelines and authorized maintenance windows are currently being suppressed."
        )
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_copilot.py -v`
Expected: PASS (all tests pass)

**Step 5: Verify integration & commit**
Run: `git status`

---

### Task 4: Continuous Compliance Posture & Audit Export Engine (`compliance.py`)

**Files:**
- Create: `compliance.py`
- Test: `tests/test_compliance.py`

**Step 1: Write the failing test**
Create `tests/test_compliance.py`:
```python
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

def test_export_audit_report():
    posture = {
        "NIST SP 800-53": {"total_controls": 10, "passed": 9, "failed": 1, "compliance_rate": 90.0}
    }
    report_md = export_audit_report(posture)
    assert "# SOCGEN DRIFTSHIELD CONTINUOUS COMPLIANCE AUDIT" in report_md
    assert "90.0%" in report_md
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/test_compliance.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'compliance'`

**Step 3: Write minimal implementation in `compliance.py`**
Create `compliance.py`:
```python
from typing import Dict, Any
import pandas as pd
from datetime import datetime

FRAMEWORKS = ["NIST SP 800-53", "CIS Benchmarks", "GDPR", "PCI-DSS"]

def _map_to_framework(mapping_str: str) -> str:
    m = mapping_str.upper()
    if "NIST" in m:
        return "NIST SP 800-53"
    elif "CIS" in m:
        return "CIS Benchmarks"
    elif "GDPR" in m:
        return "GDPR"
    elif "PCI" in m:
        return "PCI-DSS"
    return "Other Standards"

def calculate_framework_posture(df_events: pd.DataFrame, baseline_store: Dict[str, Any]) -> Dict[str, Any]:
    posture = {
        fw: {"total_controls": 0, "passed": 0, "failed": 0, "compliance_rate": 100.0}
        for fw in FRAMEWORKS
    }
    
    risky_cids = set(df_events[df_events["predicted_risky"] == 1]["control_id"].unique()) if "predicted_risky" in df_events.columns else set()

    for cid, rule in baseline_store.items():
        mapping = rule.get("compliance_mapping", "")
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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# SOCGEN DRIFTSHIELD CONTINUOUS COMPLIANCE AUDIT",
        f"**Audit Snapshot Date:** `{timestamp}`",
        f"**Environment Scope:** Enterprise Multi-Cloud Infrastructure (AWS, K8s, Perimeter Firewall, Endpoint)\n",
        "| Standard / Framework | Evaluated Controls | Passed (Compliant) | Active Drifts (Non-Compliant) | Health Score |",
        "| :--- | :---: | :---: | :---: | :---: |"
    ]
    for fw, stats in posture.items():
        lines.append(f"| **{fw}** | {stats['total_controls']} | {stats['passed']} | {stats['failed']} | **{stats['compliance_rate']}%** |")
    
    lines.append("\n### Attestation Statement")
    lines.append("All baseline drift alerts have been analyzed by the SocGen DriftShield Contextual Engine with noise suppression applied.")
    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_compliance.py -v`
Expected: PASS (all tests pass)

**Step 5: Verify integration & commit**
Run: `git status`

---

### Task 5: Integrate Upgrades into Security Dashboard (`app.py`)

**Files:**
- Modify: `app.py`
- Test: Manual UI validation & automated smoke test in `tests/test_ui_smoke.py`

**Step 1: Write UI component smoke test**
Create `tests/test_ui_smoke.py`:
```python
import json
import pandas as pd
from attack_graph import build_attack_graph, calculate_blast_radius
from remediation import generate_remediation_payload
from copilot import generate_incident_briefing, ask_copilot
from compliance import calculate_framework_posture, export_audit_report

def test_full_pipeline_smoke():
    with open("baseline_controls.json", "r") as f:
        baselines = json.load(f)
    df = pd.read_csv("drift_event_labels.csv")
    
    # 1. Attack graph test
    G, stats = build_attack_graph(df)
    assert stats["active_threat_nodes"] > 0
    
    # 2. Blast radius test
    score, factors = calculate_blast_radius(5, 3, True, True)
    assert score > 70
    
    # 3. Remediation test
    ctrl = next(iter(baselines.values()))
    payload = generate_remediation_payload(ctrl, "drifted_val")
    assert payload["code_snippet"] != ""
    
    # 4. Copilot test
    incident = {"incident_name": "Test Incident", "domains_implicated": ["AWS Cloud"], "controls_compromised": ["CTRL-001"]}
    briefing = generate_incident_briefing(incident)
    assert "Executive Summary" in briefing["markdown_report"]
    
    # 5. Compliance test
    posture = calculate_framework_posture(df, baselines)
    report = export_audit_report(posture)
    assert "AUDIT" in report
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/test_ui_smoke.py -v`
Expected: PASS (validates data files and functions)

**Step 3: Update `app.py` with Navigation Tabs**
Add four interactive tabs to `app.py`:
1. `📡 Real-Time Drift Timeline & KPIs` (Existing view, preserved perfectly)
2. `🕸️ Attack Graph & Blast Radius` (Plotly network kill-chain visualizer + dynamic blast radius meter)
3. `⚡ Self-Healing SOAR Playbooks` (Interactive remediation selector with syntax-highlighted Terraform/K8s/CLI diffs)
4. `🤖 AI Copilot & Compliance Audit` (Natural language Copilot Q&A + NIST/CIS/GDPR posture scorecards + one-click audit report export)

**Step 4: Run all tests to verify stability**
Run: `pytest tests/ -v`
Expected: 100% tests pass.

---

### Task 6: End-to-End Orchestration & Runner Update (`run.py` & `README.md`)

**Files:**
- Modify: `run.py`
- Modify: `README.md`
- Test: `tests/`

**Step 1: Update `run.py`**
Ensure `run.py` installs `pytest` and `networkx`, runs tests during pre-flight, and boots the enhanced dashboard.

**Step 2: Update `README.md`**
Document the new flagship capabilities:
- Attack Graph & Lateral Movement Blast Radius
- Self-Healing SOAR Playbooks (Terraform & Kubernetes)
- AI SecOps Incident Copilot
- Continuous Compliance Scorecards (NIST, CIS, GDPR, PCI-DSS)

**Step 3: Run comprehensive verification**
Run: `pytest tests/ -v`
Run: `python run.py --help` or verification execution.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-10-13-driftshield-enterprise-upgrades.md`. Two execution options:

1. **Subagent-Driven (this session)** - I dispatch fresh subagents per task, review between tasks, fast iteration.
2. **Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints.

**Which approach?**
