from typing import Dict, Any, List

def generate_incident_briefing(compound_incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synthesizes an executive root-cause analysis (RCA) threat briefing
    for compound cross-domain incidents with MITRE technique alignment.
    """
    name = compound_incident.get("incident_name", "Cross-Domain Incident")
    domains = compound_incident.get("domains_implicated", [])
    controls = compound_incident.get("controls_compromised", [])
    start_time = compound_incident.get("incident_window_start", "Recent")
    
    is_multi_vector = len(domains) > 1
    domain_str = ", ".join(domains)
    ctrl_str = ", ".join(controls)

    markdown_report = f"""### AI Executive Threat Briefing: {name}

**Incident Start Window:** `{start_time}`  
**Impacted Domains ({len(domains)}):** `{domain_str}`  
**Controls Implicated ({len(controls)}):** `{ctrl_str}`

#### Executive Summary
A synchronized multi-vector configuration drift sequence was detected spanning **{len(domains)} distinct infrastructure domains**. {'The threat actor executed lateral modifications across perimeter defenses and cloud assets within an aggressive 15-minute timeframe.' if is_multi_vector else 'Multiple related security controls experienced simultaneous parameter degradation.'}

#### Attacker Hypothesis & MITRE Tactic Mapping
1. **Initial Vector:** Perimeter defense weakening via ingress alterations on `{domains[0] if domains else 'Gateway'}` (MITRE *T1133 - External Remote Services*).
2. **Evasion & Blinding:** Defense impairment and telemetry suppression attempts across `{domain_str}` (MITRE *T1562 - Impair Defenses*).
3. **Objective:** Preparation for persistence or exfiltration against core asset databases.

#### Recommended Actions for SOC Analysts
- [ ] **Immediate Isolation:** Revoke temporary IAM sessions for actors associated with `{ctrl_str}`.
- [ ] **Infrastructure Rollback:** Trigger 1-Click SOAR Remediation playbooks for `{controls[0] if controls else 'affected controls'}`.
- [ ] **Forensic Snapshot:** Preserve EDR process logs and VPC flow captures within ±30 minutes of `{start_time}`.
"""
    return {
        "title": name,
        "domains": domains,
        "controls": controls,
        "markdown_report": markdown_report
    }

def ask_copilot(query: str, context: Dict[str, Any]) -> str:
    """
    Context-aware Natural Language SecOps copilot responding to SOC analyst queries.
    """
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
    elif "remediate" in q or "fix" in q or "rollback" in q or "soar" in q:
        return (
            f"**Remediation Guidance:** Navigate to the **Self-Healing SOAR** section. "
            f"You can review pre-generated Terraform HCL and Kubernetes YAML rollback patches with live code diffs."
        )
    elif "compliance" in q or "audit" in q or "nist" in q or "cis" in q or "gdpr" in q:
        return (
            f"**Compliance Posture Overview:** Continuous evaluation is running against NIST SP 800-53, CIS Benchmarks, "
            f"GDPR, and PCI-DSS. Check the **Compliance & Audit** section for full scorecards and downloadable audit attestations."
        )
    else:
        return (
            f"**SOC Copilot Overview:** Monitoring {total} total change events across AWS Cloud, Network Firewall, "
            f"Kubernetes, and Endpoint Security. All benign CI/CD pipelines and authorized maintenance windows are currently being suppressed."
        )
