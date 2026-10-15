# 🛡️ SocGen DriftShield: Enterprise Threat Verification & SOAR Platform

SocGen DriftShield is an enterprise-grade configuration monitoring, behavioral anomaly detection, and autonomous SOAR platform. It tracks multi-cloud configuration drifts, suppresses benign operational noise (CI/CD deployments, autoscaling, approved maintenance windows), models lateral threat movement, and provides 1-click self-healing remediation.

Built for enterprise cybersecurity and compliance at scale, DriftShield eliminates alert fatigue while maintaining high-fidelity observation across multi-domain infrastructure silos.

---

## 🏗️ System Architecture & Enterprise Modules

DriftShield couples high-throughput in-memory telemetry evaluation with graph-theoretic kill-chain modeling and autonomous remediation playbooks:

* **Continuous Simulation Flow (`generate-data.py`):** Enterprise data generator synthesizing over 1,000 telemetry change events mapped across 60+ dynamic master control baselines, maintenance windows, and environment contexts.
* **Contextual Analysis Engine (`engine.py`):** Algorithmic verification pipeline executing parameter-based evaluation matrices. Suppresses routine CI/CD releases and authorized maintenance operations while isolating malicious drifts.
* **Cross-Domain Timeline Correlator (`engine.py`):** Sliding time-window cluster engine tracking parallel alterations across independent silos to expose multi-stage lateral attack campaigns.
* **Threat Kill-Chain & Blast Radius Engine (`attack_graph.py`):** NetworkX-powered directed graph linking Threat Actors, Breached Controls, Asset Targets, and Infrastructure Domains with real-time lateral blast radius calculation (0–100).
* **Self-Healing SOAR Generator (`remediation.py`):** Autonomous remediation engine producing executable Terraform HCL, Kubernetes YAML patches, and CLI rollback scripts with git diff previews.
* **AI SecOps Incident Copilot (`copilot.py`):** Natural language triage assistant producing executive root-cause analysis (RCA) threat briefings and contextual recommendations.
* **Continuous Compliance & Audit Engine (`compliance.py`):** Real-time posture tracking against NIST SP 800-53, CIS Benchmarks, GDPR, and PCI-DSS, with one-click downloadable audit attestations.
* **Unified Security Console (`app.py`):** Premium 7-tab dark-mode Streamlit dashboard providing complete operational observability, interactive attack graphs, SOAR playbooks, and copilot interaction.

---

## 🚀 Quick Start (Automated Execution)

The repository includes a unified runner script that automates environment setup, dependency provisioning, data synthesis, test suite verification, and service deployment in a single step.

### Prerequisites
Ensure you have **Python 3.10+** installed on your system.

### One-Command Execution
Open your terminal window in the project root directory and run:

```bash
python run.py
```

### Running Test Verification
To execute the automated regression test suite:

```bash
python -m pytest tests/ -v
```

---

## 🏛️ Monitored Infrastructure Domains & Standards

| Domain | Key Controls Evaluated | Compliance & Frameworks |
| :--- | :--- | :--- |
| **AWS Cloud** | Root MFA, S3 public access block, CloudTrail audit logs, KMS key rotation | NIST SP 800-53, CIS AWS 1.1, GDPR Art 32 |
| **Network Firewall** | Port 8080/22 ingress restriction, egress leak prevention, session timeouts | CIS Firewall Benchmark, NIST AC-17 |
| **Kubernetes** | Privileged container denial, default-deny network policy, dashboard exposure | CIS Kubernetes 5.2.1, NIST SC-7 |
| **Endpoint Security** | EDR sensor agent heartbeat, real-time scanning, USB physical storage restrictions | NIST SI-3 / CM-2, MITRE ATT&CK (T1562) |
