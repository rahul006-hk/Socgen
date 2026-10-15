import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
import os

from remediation import generate_remediation_payload, RemediationType
from attack_graph import build_attack_graph, calculate_blast_radius, get_plotly_network_figure
from copilot import generate_incident_briefing, ask_copilot
from compliance import calculate_framework_posture, export_audit_report

# --- 1. GLOBAL BASELINE DEFINITIONS ---
BASELINE_RULES = {
    "DB_ENC_01": {"domain": "Cloud Database", "parameter": "encryption_algorithm", "expected": "AES-256", "severity": "CRITICAL", "compliance": "GDPR Art 32, PCI-DSS 3.4", "remediation": "Upgrade database encryption back to AES-256 immediately. Check CI/CD deployment variables.", "mitre_technique": "T1600.001 - Weaken Encryption: Reduce Key Space"},
    "AWS_LOG_02": {"domain": "AWS Cloud", "parameter": "cloudtrail_logging", "expected": "enabled", "severity": "CRITICAL", "compliance": "NIST SP 800-53 (SI-4), CIS AWS 3.1", "remediation": "Re-enable CloudTrail logging via AWS Console or Terraform to restore the audit trail.", "mitre_technique": "T1562.008 - Impair Defenses: Disable Cloud Logs"},
    "FW_NET_03": {"domain": "Network Firewall", "parameter": "port_8080_ingress", "expected": "blocked", "severity": "HIGH", "compliance": "CIS Firewall Benchmark 1.2", "remediation": "Close port 8080 ingress from public internet. Move vendor integration to a secure VPN.", "mitre_technique": "T1133 - External Remote Services"},
    "EDP_AGT_04": {"domain": "Endpoint Security", "parameter": "agent_status", "expected": "running", "severity": "HIGH", "compliance": "NIST SP 800-53 (CM-2)", "remediation": "Restart the endpoint security agent service on affected servers via orchestration script.", "mitre_technique": "T1562.001 - Impair Defenses: Disable or Modify Tools"}
}

# --- 2. THEME & PAGE CONFIGURATION ---
st.set_page_config(layout="wide", page_title="SocGen DriftShield Console")

# Theme state management (supports explicit Dark / Light toggle)
if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = "dark"

current_theme = st.session_state["theme_mode"]
is_dark = (current_theme == "dark")

# Complete CSS Design System Tokens
st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {{
        {"--bg-page: #0b0f19;" if is_dark else "--bg-page: #F4F6FA;"}
        {"--bg-sidebar: #111827;" if is_dark else "--bg-sidebar: #EAEEF5;"}
        {"--bg-card: #111827;" if is_dark else "--bg-card: #ffffff;"}
        {"--bg-card-hover: #1e293b;" if is_dark else "--bg-card-hover: #f8fafc;"}
        {"--border-card: rgba(255, 255, 255, 0.08);" if is_dark else "--border-card: #CBD5E1;"}
        {"--border-card-teal: rgba(20, 184, 166, 0.45);" if is_dark else "--border-card-teal: #0d9488;"}
        {"--border-subtle: #374151;" if is_dark else "--border-subtle: #CBD5E1;"}
        {"--border-divider: #1f2937;" if is_dark else "--border-divider: #CBD5E1;"}
        {"--text-main: #f9fafb;" if is_dark else "--text-main: #0F172A;"}
        {"--text-muted: #94a3b8;" if is_dark else "--text-muted: #334155;"}
        {"--text-dim: #64748b;" if is_dark else "--text-dim: #64748B;"}
        {"--text-accent: #38bdf8;" if is_dark else "--text-accent: #0284C7;"}
        --primary-accent: #f43f5e;
        {"--card-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.35);" if is_dark else "--card-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);"}
        {"--kpi-title-color: #94a3b8;" if is_dark else "--kpi-title-color: #475569;"}
        {"--kpi-value-color: #ffffff;" if is_dark else "--kpi-value-color: #0F172A;"}
        {"--delta-unresolved-color: #f87171;" if is_dark else "--delta-unresolved-color: #B42318;"}
        {"--delta-unresolved-bg: rgba(239, 68, 68, 0.15);" if is_dark else "--delta-unresolved-bg: #FEE4E2;"}
        {"--delta-unresolved-border: rgba(239, 68, 68, 0.3);" if is_dark else "--delta-unresolved-border: #FDA29B;"}
        {"--delta-suppressed-color: #34d399;" if is_dark else "--delta-suppressed-color: #067647;"}
        {"--delta-suppressed-bg: rgba(52, 211, 153, 0.15);" if is_dark else "--delta-suppressed-bg: #D1FADF;"}
        {"--delta-suppressed-border: rgba(52, 211, 153, 0.3);" if is_dark else "--delta-suppressed-border: #6CE9A6;"}
        --tag-bg: #e11d48;
        --tag-text: #ffffff;
        --nav-row-bg: transparent;
        {"--nav-row-hover: rgba(255, 255, 255, 0.06);" if is_dark else "--nav-row-hover: rgba(0, 0, 0, 0.05);"}
        {"--nav-active-bg: rgba(244, 63, 94, 0.16);" if is_dark else "--nav-active-bg: #ffffff;"}
        --nav-active-bar: #f43f5e;
        {"--nav-active-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);" if is_dark else "--nav-active-shadow: 0 2px 6px rgba(15, 23, 42, 0.08);"}
        {"--nav-text: #94a3b8;" if is_dark else "--nav-text: #334155;"}
        {"--nav-text-active: #ffffff;" if is_dark else "--nav-text-active: #0F172A;"}
        {"--tab-border: #1f2937;" if is_dark else "--tab-border: #CBD5E1;"}
        --tab-active-border: #f43f5e;
        {"--tab-text-inactive: #64748b;" if is_dark else "--tab-text-inactive: #475569;"}
        --tab-text-active: #f43f5e;
        {"--expander-bg: #111827;" if is_dark else "--expander-bg: #ffffff;"}
        {"--expander-border: #374151;" if is_dark else "--expander-border: #CBD5E1;"}
        {"--expander-text: #f9fafb;" if is_dark else "--expander-text: #0F172A;"}
        {"--incident-bg: #1f2937;" if is_dark else "--incident-bg: #ffffff;"}
        {"--incident-inner-bg: #111827;" if is_dark else "--incident-inner-bg: #F8FAFC;"}
        {"--incident-text: #f9fafb;" if is_dark else "--incident-text: #0F172A;"}
        {"--code-bg: #0f172a;" if is_dark else "--code-bg: #F8FAFC;"}
        {"--code-border: #1e293b;" if is_dark else "--code-border: #CBD5E1;"}
        {"--btn-bg: #1f2937;" if is_dark else "--btn-bg: #ffffff;"}
        {"--btn-border: #374151;" if is_dark else "--btn-border: #CBD5E1;"}
        {"--btn-text: #f9fafb;" if is_dark else "--btn-text: #0F172A;"}
        {"--btn-hover-bg: #374151;" if is_dark else "--btn-hover-bg: #F1F5F9;"}
        {"--input-bg: #111827;" if is_dark else "--input-bg: #ffffff;"}
        {"--input-border: #374151;" if is_dark else "--input-border: #CBD5E1;"}
    }}

    html, body, .stApp, .main, p, h1, h2, h3, h4, h5, h6 {{
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        color: var(--text-main) !important;
    }}

    code, pre {{
        font-family: 'JetBrains Mono', monospace !important;
    }}

    .main, .stApp {{
        background-color: var(--bg-page) !important;
    }}

    /* Top Streamlit Header Bar Fix */
    header[data-testid="stHeader"],
    .stAppHeader,
    div[data-testid="stToolbar"] {{
        background-color: var(--bg-page) !important;
        color: var(--text-main) !important;
    }}
    div[data-testid="stDecoration"] {{
        display: none !important;
    }}

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {{
        background-color: var(--bg-sidebar) !important;
        border-right: 1px solid var(--border-divider) !important;
    }}
    section[data-testid="stSidebar"] > div {{
        background-color: var(--bg-sidebar) !important;
    }}

    /* Brand Block in Sidebar */
    .sidebar-brand-block {{
        padding: 4px 10px 14px 10px;
        margin-bottom: 6px;
    }}
    .brand-badge {{
        display: inline-block;
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        background: rgba(244, 63, 94, 0.15);
        color: #f43f5e;
        padding: 2px 7px;
        border-radius: 4px;
        margin-bottom: 6px;
        border: 1px solid rgba(244, 63, 94, 0.25);
    }}
    .sidebar-brand-title {{
        font-size: 1.05rem;
        font-weight: 800;
        letter-spacing: -0.01em;
        color: var(--text-main);
        line-height: 1.2;
    }}
    .sidebar-brand-subtitle {{
        font-size: 0.72rem;
        font-weight: 500;
        color: var(--text-muted);
        letter-spacing: 0.01em;
        margin-top: 2px;
    }}

    /* Buttons: Primary & Secondary (Theme switcher & Actions) */
    div.stButton > button[kind="primary"],
    button[data-testid="baseButton-primary"] {{
        background-color: #f43f5e !important;
        border: 1px solid #e11d48 !important;
        color: #ffffff !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        box-shadow: 0 2px 6px rgba(244, 63, 94, 0.25) !important;
    }}

    div.stButton > button[kind="secondary"],
    button[data-testid="baseButton-secondary"],
    div[data-testid="stSidebar"] button {{
        background-color: var(--btn-bg) !important;
        border: 1px solid var(--btn-border) !important;
        color: var(--btn-text) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        box-shadow: var(--card-shadow) !important;
    }}
    div.stButton > button[kind="secondary"]:hover,
    button[data-testid="baseButton-secondary"]:hover,
    div[data-testid="stSidebar"] button:hover {{
        background-color: var(--btn-hover-bg) !important;
        color: var(--text-main) !important;
    }}

    /* Aesthetic Vertical Navigation Menu in Sidebar */
    div[data-testid="stSidebar"] div[role="radiogroup"] {{
        gap: 3px !important;
        display: flex !important;
        flex-direction: column !important;
    }}
    
    /* Turn each radio item into a sleek modern menu pill */
    div[data-testid="stSidebar"] div[role="radiogroup"] > label {{
        padding: 10px 14px !important;
        margin: 0 !important;
        border-radius: 8px !important;
        width: 100% !important;
        border: 1px solid transparent !important;
        border-left: 3px solid transparent !important;
        background: var(--nav-row-bg) !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
        cursor: pointer !important;
        display: flex !important;
        align-items: center !important;
    }}

    /* Hide the radio circle button and all internal non-text elements */
    div[data-testid="stSidebar"] div[role="radiogroup"] label div:not([data-testid="stMarkdownContainer"]),
    div[data-testid="stSidebar"] div[role="radiogroup"] label input,
    div[data-testid="stSidebar"] [data-baseweb="radio"] > div:first-of-type,
    div[data-testid="stSidebar"] [data-baseweb="radio"] span {{
        display: none !important;
        width: 0 !important;
        height: 0 !important;
        opacity: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
        visibility: hidden !important;
    }}
    
    div[data-testid="stSidebar"] div[role="radiogroup"] > label div[data-testid="stMarkdownContainer"] p {{
        font-size: 0.88rem !important;
        font-weight: 500 !important;
        color: var(--nav-text) !important;
        margin: 0 !important;
        letter-spacing: 0.01em !important;
        transition: color 0.15s ease !important;
    }}

    /* Hover state with subtle translation */
    div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {{
        background: var(--nav-row-hover) !important;
        transform: translateX(2px) !important;
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover div[data-testid="stMarkdownContainer"] p {{
        color: var(--text-main) !important;
    }}

    /* Active state: left accent bar + elevated background */
    div[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked),
    div[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] {{
        background: var(--nav-active-bg) !important;
        border-left: 3px solid var(--nav-active-bar) !important;
        border-color: rgba(244, 63, 94, 0.25) !important;
        box-shadow: var(--nav-active-shadow) !important;
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) div[data-testid="stMarkdownContainer"] p,
    div[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] div[data-testid="stMarkdownContainer"] p {{
        color: var(--nav-text-active) !important;
        font-weight: 700 !important;
    }}

    /* Sidebar Dividers & Section Labels */
    .sidebar-divider {{
        height: 1px;
        background: var(--border-divider);
        margin: 14px 0 12px 0;
        border: none;
    }}
    .sidebar-section-header {{
        font-size: 0.7rem;
        font-weight: 800;
        letter-spacing: 0.12em;
        color: var(--text-muted);
        text-transform: uppercase;
        padding: 4px 10px 2px 10px;
    }}
    .sidebar-section-helper {{
        font-size: 0.75rem;
        color: var(--text-dim);
        padding: 0 10px 10px 10px;
        line-height: 1.3;
    }}

    /* Multiselect Styling: Crisp in both Light and Dark mode */
    div[data-baseweb="select"],
    div[data-baseweb="select"] > div,
    div[data-testid="stSidebar"] div[data-baseweb="select"],
    div[data-testid="stSidebar"] div[data-baseweb="select"] > div {{
        background-color: var(--input-bg) !important;
        border: 1px solid var(--input-border) !important;
        border-radius: 8px !important;
        color: var(--text-main) !important;
    }}
    div[data-testid="stSidebar"] div[data-baseweb="select"] svg {{
        fill: var(--text-muted) !important;
    }}
    span[data-baseweb="tag"],
    div[data-baseweb="tag"] {{
        background-color: var(--tag-bg) !important;
        color: var(--tag-text) !important;
        padding: 4px 10px !important;
        border-radius: 4px !important;
        font-size: 0.78rem !important;
        font-weight: 600 !important;
        cursor: default !important;
    }}
    span[data-baseweb="tag"] span,
    span[data-baseweb="tag"] svg {{
        color: var(--tag-text) !important;
        fill: var(--tag-text) !important;
    }}

    /* Header Styling */
    .header-container {{
        margin-top: 0.2rem;
        margin-bottom: 0.8rem;
    }}
    .main-brand-title {{
        font-size: 2.8rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.03em !important;
        color: var(--text-main) !important;
        line-height: 1.05 !important;
        margin: 0 !important;
    }}
    .main-brand-subtitle {{
        font-size: 1.22rem !important;
        font-weight: 500 !important;
        letter-spacing: 0.01em !important;
        color: var(--text-muted) !important;
        margin-top: 0.35rem !important;
        margin-bottom: 0.6rem !important;
    }}
    .main-brand-desc {{
        font-size: 0.92rem !important;
        color: var(--text-muted) !important;
        margin: 0 !important;
        line-height: 1.5 !important;
    }}

    /* Fixed KPI Cards - No Text Clipping */
    div[data-testid="stMetric"] {{
        background: var(--bg-card) !important;
        border: 1px solid var(--border-card) !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        box-shadow: var(--card-shadow) !important;
        transition: all 0.2s ease !important;
        min-height: 110px !important;
    }}
    div[data-testid="stMetric"]:hover {{
        transform: translateY(-2px) !important;
    }}
    div[data-testid="stHorizontalBlock"] > div:nth-child(3) [data-testid="stMetric"] {{
        border: 1px solid var(--border-card-teal) !important;
    }}
    div[data-testid="stMetricLabel"] > div {{
        font-size: 0.75rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.08em !important;
        font-weight: 600 !important;
        color: var(--kpi-title-color) !important;
        white-space: normal !important;
        word-wrap: break-word !important;
        line-height: 1.25 !important;
        margin-bottom: 8px !important;
    }}
    div[data-testid="stMetricValue"] > div {{
        font-size: 2rem !important;
        font-weight: 800 !important;
        color: var(--kpi-value-color) !important;
        line-height: 1.1 !important;
    }}

    /* High-contrast status badges */
    div[data-testid="stHorizontalBlock"] > div:nth-child(2) [data-testid="stMetricDelta"] {{
        color: var(--delta-unresolved-color) !important;
        background: var(--delta-unresolved-bg) !important;
        border: 1px solid var(--delta-unresolved-border) !important;
        padding: 3px 8px !important;
        border-radius: 5px !important;
        font-weight: 700 !important;
        font-size: 0.78rem !important;
        display: inline-flex !important;
        align-items: center !important;
    }}
    div[data-testid="stHorizontalBlock"] > div:nth-child(2) [data-testid="stMetricDelta"] svg {{
        fill: var(--delta-unresolved-color) !important;
        color: var(--delta-unresolved-color) !important;
    }}

    div[data-testid="stHorizontalBlock"] > div:nth-child(3) [data-testid="stMetricDelta"] {{
        color: var(--delta-suppressed-color) !important;
        background: var(--delta-suppressed-bg) !important;
        border: 1px solid var(--delta-suppressed-border) !important;
        padding: 3px 8px !important;
        border-radius: 5px !important;
        font-weight: 700 !important;
        font-size: 0.78rem !important;
        display: inline-flex !important;
        align-items: center !important;
    }}
    div[data-testid="stHorizontalBlock"] > div:nth-child(3) [data-testid="stMetricDelta"] svg {{
        fill: var(--delta-suppressed-color) !important;
        color: var(--delta-suppressed-color) !important;
    }}

    /* Aesthetic Top View Header Block */
    .view-header-strip {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 16px;
        background: var(--bg-card);
        border: 1px solid var(--border-card);
        border-radius: 10px;
        margin-bottom: 20px;
        box-shadow: var(--card-shadow);
    }}
    .view-strip-left {{
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .view-strip-badge {{
        font-size: 0.7rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        background: var(--nav-active-bg);
        color: var(--primary-accent);
        padding: 4px 8px;
        border-radius: 5px;
        border: 1px solid rgba(244, 63, 94, 0.25);
    }}
    .view-strip-title {{
        font-size: 1.15rem;
        font-weight: 700;
        color: var(--text-main);
    }}
    .view-strip-desc {{
        font-size: 0.85rem;
        color: var(--text-muted);
    }}

    /* Incident Cards */
    .incident-card {{
        background: var(--incident-bg);
        border: 1px solid var(--border-subtle);
        border-left: 5px solid #ef4444;
        border-radius: 0 8px 8px 0;
        padding: 16px 18px;
        margin-bottom: 14px;
        box-shadow: var(--card-shadow);
    }}
    .incident-inner {{
        background-color: var(--incident-inner-bg);
        padding: 12px;
        border-radius: 6px;
        margin-top: 10px;
        font-size: 14px;
        border: 1px solid var(--border-subtle);
    }}

    /* Clean badges without emojis */
    .clean-badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        margin-left: 6px;
    }}
    .badge-heartbeat {{ background: #f97316; color: #ffffff; }}
    .badge-sequence {{ background: #a855f7; color: #ffffff; }}
    .badge-critical {{ background: #ef4444; color: #ffffff; }}

    /* Expanders & Code */
    div[data-testid="stExpander"] {{
        background-color: var(--expander-bg) !important;
        border: 1px solid var(--expander-border) !important;
        border-radius: 8px !important;
        margin-bottom: 10px !important;
        box-shadow: var(--card-shadow) !important;
    }}
    div[data-testid="stExpander"] summary {{
        color: var(--text-main) !important;
        font-weight: 600 !important;
    }}
    div[data-testid="stCodeBlock"] {{
        background: var(--code-bg) !important;
        border: 1px solid var(--code-border) !important;
        border-radius: 6px !important;
    }}
    hr {{
        border-color: var(--border-divider) !important;
        background-color: var(--border-divider) !important;
        margin: 1.25rem 0 !important;
    }}
    </style>
""", unsafe_allow_html=True)


# --- 3. DATA INGESTION ENGINE ---
@st.cache_data
def load_and_validate_data():
    if not os.path.exists("drift_event_labels.csv"):
        return None
    df = pd.read_csv("drift_event_labels.csv")
    
    if 'predicted_risky' not in df.columns:
        try:
            from engine import analyze_and_predict_drift
            df = analyze_and_predict_drift()
        except Exception as e:
            st.error(f"Failed running engine: {e}")
            st.stop()
            
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

df_raw = load_and_validate_data()

if df_raw is None:
    st.error("Missing Telemetry Data Foundation")
    st.info("The application could not locate `drift_event_labels.csv`. Please initialize your local data pipeline:")
    st.code("python generate_data.py\npython engine.py")
    st.stop()

if os.path.exists("baseline_controls.json"):
    with open("baseline_controls.json", "r") as f:
        baseline_rules = json.load(f)
else:
    baseline_rules = BASELINE_RULES

try:
    from engine import run_cross_domain_correlator
    compounds = run_cross_domain_correlator(df_raw)
except Exception:
    st.warning("Core engine correlation functions missing. Falling back to internal calculation logic.")
    compounds = []

# --- 4. NAVIGATION DEFINITIONS & SIDEBAR AS A REAL MENU ---
MENU_ITEMS = [
    "Observability",
    "Cross-Domain Correlation",
    "Kill-Chain & Blast Radius",
    "Self-Healing SOAR",
    "AI SecOps Copilot",
    "Compliance & Audit",
    "Incident Remediation Log",
    "Engine Validation Scorecard"
]

MENU_DESCRIPTIONS = {
    "Observability": "Spatial-temporal risk distribution and telemetry activity stream.",
    "Cross-Domain Correlation": "Multi-vector attack detection across independent enterprise silos within a 15-minute sliding window.",
    "Kill-Chain & Blast Radius": "Directed graph linkages and lateral blast radius impact analysis.",
    "Self-Healing SOAR": "Autonomous generation of Terraform HCL, Kubernetes YAML, and CLI rollback scripts.",
    "AI SecOps Copilot": "Automated root-cause analysis (RCA) briefings and interactive SecOps Q&A.",
    "Compliance & Audit": "Continuous evaluation against NIST SP 800-53, CIS, GDPR, and PCI-DSS.",
    "Incident Remediation Log": "Prioritized inventory of active drifted controls with regulatory and MITRE mappings.",
    "Engine Validation Scorecard": "Statistical precision, recall, and benign suppression rate benchmarks."
}

if "active_nav" not in st.session_state:
    st.session_state["active_nav"] = "Observability"

with st.sidebar:
    # 1. Brand Block
    st.markdown("""
        <div class="sidebar-brand-block">
            <div class="brand-badge">ENTERPRISE SOC</div>
            <div class="sidebar-brand-title">SocGen DriftShield</div>
            <div class="sidebar-brand-subtitle">Context-Aware Threat Engine</div>
        </div>
    """, unsafe_allow_html=True)

    # 2. Seamless Theme Switcher Button Row (High contrast in both Light & Dark modes)
    t_col1, t_col2 = st.columns(2)
    with t_col1:
        if st.button("Light Mode", key="btn_switch_light", use_container_width=True, type="primary" if not is_dark else "secondary"):
            st.session_state["theme_mode"] = "light"
            st.rerun()
    with t_col2:
        if st.button("Dark Mode", key="btn_switch_dark", use_container_width=True, type="primary" if is_dark else "secondary"):
            st.session_state["theme_mode"] = "dark"
            st.rerun()

    st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-section-header">NAVIGATION</div>', unsafe_allow_html=True)

    # 3. Aesthetic Sidebar Navigation Menu
    current_index = MENU_ITEMS.index(st.session_state["active_nav"]) if st.session_state["active_nav"] in MENU_ITEMS else 0
    selected_sidebar_item = st.radio(
        "Menu",
        options=MENU_ITEMS,
        index=current_index,
        key="nav_sidebar_radio",
        label_visibility="collapsed"
    )
    if selected_sidebar_item != st.session_state["active_nav"]:
        st.session_state["active_nav"] = selected_sidebar_item
        st.rerun()

    st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-section-header">FILTERS</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-section-helper">Filter dashboard contexts in real-time.</div>', unsafe_allow_html=True)

    # 4. Filters with current behaviour
    selected_domains = st.multiselect(
        "Tech Domains:",
        options=list(df_raw["domain"].unique()),
        default=list(df_raw["domain"].unique())
    )

    selected_envs = st.multiselect(
        "Environment:",
        options=list(df_raw["env"].unique()),
        default=list(df_raw["env"].unique())
    )

    st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
    st.markdown("""
        <div class="sidebar-footer">
            <div class="sidebar-footer-status">SYSTEM STATUS: OPERATIONAL</div>
            <div class="sidebar-footer-version">Enterprise Verification v2.4</div>
        </div>
    """, unsafe_allow_html=True)

# Filter telemetry data
df = df_raw[df_raw["domain"].isin(selected_domains) & df_raw["env"].isin(selected_envs)].copy()

# --- 5. REARRANGED TITLE BLOCK ---
st.markdown("""
    <div class="header-container">
        <h1 class="main-brand-title">SocGen</h1>
        <div class="main-brand-subtitle">DriftShield: Context-Aware Threat Verification Console</div>
        <p class="main-brand-desc">Multi-domain continuous monitoring tracking drift signatures, suppression rates, and horizontal cyberattack vectors.</p>
    </div>
""", unsafe_allow_html=True)
st.markdown("---")

# --- 6. KPI METRICS CARDS (FIXED PADDING & NO TEXT CLIPPING) ---
total_logs = len(df)
active_alerts = len(df[df["predicted_risky"] == 1])
suppressed_noise = len(df[df["engine_status_summary"].str.contains("Suppressed", na=False)])
health_metric = ((total_logs - active_alerts) / total_logs) * 100 if total_logs > 0 else 100

m1, m2, m3, m4 = st.columns(4)
m1.metric("Telemetry Stream Volume", f"{total_logs:,}")
m2.metric("Active Actionable Alerts", active_alerts, delta=f"{active_alerts} Unresolved", delta_color="inverse")
m3.metric("Benign Events Filtered", suppressed_noise, delta="Alert Fatigue Suppressed")
m4.metric("Ecosystem Compliance Score", f"{health_metric:.2f}%")

st.markdown("---")

# --- 7. AESTHETIC ACTIVE VIEW STRIP ---
active_tab = st.session_state["active_nav"]
desc = MENU_DESCRIPTIONS.get(active_tab, "Enterprise Security Module")

st.markdown(f"""
    <div class="view-header-strip">
        <div class="view-strip-left">
            <div class="view-strip-badge">ACTIVE VIEW</div>
            <div class="view-strip-title">{active_tab}</div>
        </div>
        <div class="view-strip-desc">{desc}</div>
    </div>
""", unsafe_allow_html=True)

# Helper function to guarantee ultra-high contrast on Plotly charts for both Dark and Light modes
def apply_chart_theme(fig, is_dark_mode: bool, title: str = ""):
    text_color = "#f9fafb" if is_dark_mode else "#0F172A"
    grid_color = "rgba(255, 255, 255, 0.08)" if is_dark_mode else "rgba(15, 23, 42, 0.08)"
    card_bg = "#111827" if is_dark_mode else "#ffffff"

    fig.update_layout(
        template="plotly_dark" if is_dark_mode else "plotly_white",
        paper_bgcolor=card_bg,
        plot_bgcolor=card_bg,
        font=dict(
            family="Plus Jakarta Sans, sans-serif",
            color=text_color,
            size=12
        ),
        title=dict(
            text=f"<b>{title}</b>" if title else None,
            font=dict(color=text_color, size=14, family="Plus Jakarta Sans, sans-serif")
        ) if title else None,
        xaxis=dict(
            color=text_color,
            tickfont=dict(color=text_color, size=11, family="Plus Jakarta Sans, sans-serif"),
            title_font=dict(color=text_color, size=12, family="Plus Jakarta Sans, sans-serif"),
            gridcolor=grid_color,
            zerolinecolor=grid_color
        ),
        yaxis=dict(
            color=text_color,
            tickfont=dict(color=text_color, size=11, family="Plus Jakarta Sans, sans-serif"),
            title_font=dict(color=text_color, size=12, family="Plus Jakarta Sans, sans-serif"),
            gridcolor=grid_color,
            zerolinecolor=grid_color
        ),
        legend=dict(
            font=dict(color=text_color, size=11, family="Plus Jakarta Sans, sans-serif"),
            title_font=dict(color=text_color, size=12, family="Plus Jakarta Sans, sans-serif"),
            bgcolor="rgba(0,0,0,0)"
        ),
        coloraxis_colorbar=dict(
            title_font=dict(color=text_color, size=11, family="Plus Jakarta Sans, sans-serif"),
            tickfont=dict(color=text_color, size=10, family="Plus Jakarta Sans, sans-serif")
        ),
        margin=dict(t=35, b=35, l=35, r=35)
    )
    return fig

# --- 8. SECTION CONTENT ROUTING ---

# === 1. OBSERVABILITY ===
if active_tab == "Observability":
    col_l, col_r = st.columns(2)
    
    with col_l:
        st.subheader("Control Health Distribution Heatmap")
        st.caption("Distribution of active risk levels across monitored enterprise technical domains.")
        active_df = df[df["predicted_risky"] == 1]
        if not active_df.empty:
            heat_matrix = active_df.groupby(["domain", "severity"]).size().reset_index(name="Alert Counts")
            fig_heat = px.density_heatmap(
                heat_matrix, x="severity", y="domain", z="Alert Counts",
                color_continuous_scale="Reds", text_auto=True,
                labels={"severity": "Risk Severity", "domain": "Enterprise Domain"}
            )
            apply_chart_theme(fig_heat, is_dark, title="")
            st.plotly_chart(fig_heat, use_container_width=True)
        else:
            st.success("No active configuration deviations found for chosen parameters.")
            
    with col_r:
        st.subheader("Chronology Time Stream Activity Log")
        st.caption("Real-time chronological events classified by Contextual Engine.")
        timeline_slice = df.head(150)
        fig_time = px.scatter(
            timeline_slice, x="timestamp", y="domain", color="engine_status_summary",
            size="calculated_risk_score", hover_data=["control_id", "new_value"],
            title="Contextual Telemetry Classification Stream"
        )
        apply_chart_theme(fig_time, is_dark, title="Contextual Telemetry Classification Stream")
        st.plotly_chart(fig_time, use_container_width=True)

# === 2. CROSS-DOMAIN CORRELATION ===
elif active_tab == "Cross-Domain Correlation":
    st.subheader("Time-Window Multi-Vector Attack Patterns")
    st.caption("Correlating minor isolated changes occurring across independent enterprise silos within a sliding 15-minute window.")
    st.markdown("---")
    
    if compounds:
        for index, item in enumerate(compounds[:5]):
            with st.expander(f"{item['incident_name']} — Flagged Event Group #{index+1}"):
                c1, c2 = st.columns([1, 2])
                with c1:
                    st.error("Implicated Vector Paths:")
                    st.write(f"Cross-Domain Grouping: {', '.join(item['domains_implicated'])}")
                    st.write(f"Core Technical Controls: {', '.join(item['controls_compromised'])}")
                    st.caption(f"Initial Drift Timestamp: {item['incident_window_start']}")
                with c2:
                    st.warning("Threat Intelligence Assessment Narrative:")
                    st.write(
                        "Independent logging nodes viewed these infrastructure modifications as independent changes. "
                        "However, correlation logic flags high-proximity cluster activity (e.g., Firewall modification paired "
                        "with cloud audit trail log deletion), signaling an active internal breach or multi-stage lateral movement pattern."
                    )
    else:
        st.success("No multi-domain compound attack chains detected across current window selections.")

# === 3. KILL-CHAIN & BLAST RADIUS ===
elif active_tab == "Kill-Chain & Blast Radius":
    st.subheader("Threat Kill-Chain Topology & Lateral Movement")
    st.caption("Visualizing directed graph linkages between Threat Actors, Compromised Baseline Controls, Asset Targets, and Domains.")
    st.markdown("---")
    
    G, graph_stats = build_attack_graph(df)
    
    active_threat_df = df[df["predicted_risky"] == 1]
    has_crit = (active_threat_df["severity"] == "CRITICAL").any() if not active_threat_df.empty else False
    has_prod = (active_threat_df["env"] == "production").any() if not active_threat_df.empty else False
    
    radius_score, radius_factors = calculate_blast_radius(
        num_compromised_controls=len(active_threat_df["control_id"].unique()) if not active_threat_df.empty else 0,
        num_domains=len(active_threat_df["domain"].unique()) if not active_threat_df.empty else 0,
        has_critical=has_crit,
        has_production=has_prod
    )
    
    b1, b2, b3 = st.columns([1, 1, 2])
    b1.metric("Graph Nodes Implicated", graph_stats["active_threat_nodes"])
    b2.metric("Lateral Attack Paths", graph_stats["attack_paths"])
    b3.metric("Lateral Blast Radius Score", f"{radius_score}/100", delta="High Threat Impact" if radius_score >= 60 else "Moderate Impact", delta_color="inverse")
    
    st.info(f"Blast Radius Contributing Factors: {' • '.join(radius_factors)}")
    
    fig_network = get_plotly_network_figure(G, theme="dark" if is_dark else "light")
    st.plotly_chart(fig_network, use_container_width=True)

# === 4. SELF-HEALING SOAR ===
elif active_tab == "Self-Healing SOAR":
    st.subheader("Self-Healing SOAR Playbooks & Infrastructure Rollback")
    st.caption("Automated generation of Terraform HCL patches, Kubernetes deployment manifests, and CLI remediation scripts.")
    st.markdown("---")
    
    active_threat_df = df[df["predicted_risky"] == 1].copy()
    if not active_threat_df.empty:
        soar_ctrl_options = list(active_threat_df["control_id"].unique())
        selected_cid = st.selectbox(
            "Select Drifted Control to Remediate:", 
            soar_ctrl_options,
            format_func=lambda cid: f"{cid} — {baseline_rules.get(cid, {}).get('parameter', 'Control')} ({baseline_rules.get(cid, {}).get('domain', 'Domain')} • {baseline_rules.get(cid, {}).get('asset_target', 'Asset')})"
        )
        
        sample_row = active_threat_df[active_threat_df["control_id"] == selected_cid].iloc[0]
        ctrl_def = baseline_rules.get(selected_cid, {
            "control_id": selected_cid,
            "domain": sample_row["domain"],
            "asset_target": sample_row["asset_target"],
            "parameter": sample_row["parameter"],
            "expected_value": sample_row["old_value"],
            "severity": sample_row["severity"],
            "remediation_steps": "Restore system baseline configuration."
        })
        
        remediation_payload = generate_remediation_payload(ctrl_def, observed_value=sample_row["new_value"])
        
        s1, s2 = st.columns([1, 1])
        with s1:
            st.markdown(f"#### Target: `{remediation_payload['asset']}` ({remediation_payload['domain']})")
            st.write(f"**Parameter:** `{remediation_payload['parameter']}`")
            st.write(f"**Current Drifted State:** `{remediation_payload['observed_value']}`")
            st.write(f"**Baseline Expected State:** `{remediation_payload['expected_value']}`")
            st.markdown(f"**Playbook Action:** {remediation_payload['remediation_summary']}")
            
            st.markdown("##### Git State Rollback Preview:")
            st.code(remediation_payload["rollback_diff"], language="diff")
            
        with s2:
            st.markdown(f"#### Generated Playbook: `{remediation_payload['remediation_type']}`")
            st.code(remediation_payload["code_snippet"], language="hcl" if "Terraform" in remediation_payload["remediation_type"] else "yaml" if "Kubernetes" in remediation_payload["remediation_type"] else "bash")
            
            file_ext = 'tf' if 'Terraform' in remediation_payload['remediation_type'] else 'yaml' if 'Kubernetes' in remediation_payload['remediation_type'] else 'sh'
            st.download_button(
                label=f"Download {remediation_payload['remediation_type']} Patch",
                data=remediation_payload["code_snippet"],
                file_name=f"remediate_{selected_cid}.{file_ext}",
                mime="text/plain",
                key=f"btn_download_soar_{selected_cid}"
            )
            st.success("Ready for pipeline execution or dry-run commit.")
    else:
        st.success("All infrastructure controls are operating in full baseline compliance.")

# === 5. AI SECOPS COPILOT ===
elif active_tab == "AI SecOps Copilot":
    st.subheader("AI SecOps Incident Copilot")
    st.caption("Intelligent threat synthesis, plain-English root-cause analysis (RCA), and conversational triage assistant.")
    st.markdown("---")
    
    if compounds:
        top_incident = compounds[0]
        briefing = generate_incident_briefing(top_incident)
        st.markdown(briefing["markdown_report"])
    else:
        st.info("No active multi-domain compound threat cluster currently in progress.")
        
    st.markdown("---")
    st.subheader("Ask DriftShield SecOps Copilot")
    
    copilot_context = {
        "total_drifts": len(df),
        "critical_alerts": len(df[(df["predicted_risky"] == 1) & (df["severity"] == "CRITICAL")]),
        "high_alerts": len(df[(df["predicted_risky"] == 1) & (df["severity"] == "HIGH")])
    }

    if "copilot_history" not in st.session_state:
        st.session_state.copilot_history = []
    if "copilot_preset" not in st.session_state:
        st.session_state.copilot_preset = ""
    
    c_col1, c_col2, c_col3 = st.columns(3)
    if c_col1.button("What should I triage first?", key="btn_triage_first"):
        st.session_state.copilot_preset = "What should I triage first?"
    if c_col2.button("What is the current blast radius?", key="btn_blast_radius"):
        st.session_state.copilot_preset = "What is the current blast radius?"
    if c_col3.button("Show compliance audit summary", key="btn_audit_summary"):
        st.session_state.copilot_preset = "Show compliance audit summary"
        
    user_query = st.text_input(
        "Ask a question about current telemetry, drifts, or remediation:", 
        value=st.session_state.copilot_preset, 
        placeholder="e.g. How many critical alerts need immediate triage?",
        key="txt_copilot_query"
    )
    if user_query:
        answer = ask_copilot(user_query, copilot_context)
        if not st.session_state.copilot_history or st.session_state.copilot_history[0][0] != user_query:
            st.session_state.copilot_history.insert(0, (user_query, answer))

    if st.session_state.copilot_history:
        for q_entry, a_entry in st.session_state.copilot_history[:3]:
            st.markdown(f"**Analyst:** *{q_entry}*")
            st.markdown(f"> DriftShield Copilot: {a_entry}")
            st.markdown("---")

# === 6. COMPLIANCE & AUDIT ===
elif active_tab == "Compliance & Audit":
    st.subheader("Continuous Compliance Posture & Regulatory Health")
    st.caption("Real-time alignment against NIST SP 800-53, CIS Benchmarks, GDPR, and PCI-DSS.")
    st.markdown("---")
    
    posture = calculate_framework_posture(df, baseline_rules, selected_domains=selected_domains)
    
    cp1, cp2, cp3, cp4 = st.columns(4)
    cols = [cp1, cp2, cp3, cp4]
    for idx, (fw, stats) in enumerate(posture.items()):
        if idx < len(cols):
            cols[idx].metric(
                label=fw,
                value=f"{stats['compliance_rate']}%",
                delta=f"{stats['passed']}/{stats['total_controls']} Controls"
            )
            
    st.markdown("---")
    st.subheader("One-Click Compliance Evidence Export")
    st.caption("Generate a verifiable audit report for regulators, CISO, and external compliance assessors.")
    
    audit_report_content = export_audit_report(posture)
    st.markdown(audit_report_content)
    
    st.download_button(
        label="Export Formal Compliance Attestation (.md)",
        data=audit_report_content,
        file_name="socgen_driftshield_compliance_audit.md",
        mime="text/markdown",
        key="btn_download_compliance_audit"
    )

# === 7. INCIDENT REMEDIATION LOG ===
elif active_tab == "Incident Remediation Log":
    st.subheader("Actionable Compliance Anomalies & Sequenced Playbooks")
    st.caption("Detailed inventory of active drifted controls with regulatory and MITRE ATT&CK mapping.")
    st.markdown("---")
    
    active_df = df[df["predicted_risky"] == 1].copy()

    def _priority(status):
        s = str(status)
        if "Heartbeat" in s:
            return 0
        if "Sequence" in s:
            return 1
        return 2
    active_df["_sort_priority"] = active_df["engine_status_summary"].apply(_priority)
    active_alerts_only = active_df.sort_values("_sort_priority").head(30)
    
    if not active_alerts_only.empty:
        for _, row in active_alerts_only.iterrows():
            cid = row['control_id']
            is_heartbeat = "Heartbeat" in str(row.get("engine_status_summary", ""))
            is_sequence  = "Sequence" in str(row.get("engine_status_summary", ""))
            
            if cid in baseline_rules:
                rule = baseline_rules[cid]
                comp_mapping = rule['compliance_mapping']
                remediation = rule['remediation_steps']
                mitre_technique = rule.get('mitre_technique', 'Not Mapped')
            else:
                comp_mapping = "NIST SP 800-53 (CM-2) — Endpoint Telemetry Baseline" if is_heartbeat else "Unknown Standard Mapping"
                remediation = "Investigate endpoint agent and restore live telemetry heartbeat signal." if is_heartbeat else "Investigate system settings manually."
                mitre_technique = "T1562.001 - Impair Defenses: Disable or Modify Tools" if is_heartbeat else "Not Mapped"

            border_color = "#f97316" if is_heartbeat else ("#a855f7" if is_sequence else "#ef4444")
            alert_type_badge = (
                '<span class="clean-badge badge-heartbeat">HEARTBEAT ALERT</span>'
                if is_heartbeat else
                '<span class="clean-badge badge-sequence">SEQUENCE ALERT</span>'
                if is_sequence else
                '<span class="clean-badge badge-critical">CRITICAL ALERT</span>'
            )

            st.markdown(f"""
                <div class="incident-card" style="border-left-color: {border_color};">
                    <h4 style="margin: 0 0 8px 0; font-size: 1.05rem;">Incident ID: {row['event_id']} — Domain: {row['domain']} (Risk Score: {row['calculated_risk_score']}) {alert_type_badge}</h4>
                    <p style="margin: 4px 0;"><b>Parameter Targeted:</b> <code>{row['parameter']}</code> | <b>Environment:</b> <code>{str(row['env']).upper()}</code></p>
                    <p style="margin: 4px 0;"><b>Observed State:</b> <span style="color:#f87171; font-weight:700;">{row['new_value']}</span> (Baseline Expected: <b>{row['old_value']}</b>)</p>
                    <p style="color:var(--text-muted); font-size:13px; margin: 4px 0 8px 0;"><i>Engine Classification: {row['engine_status_summary']}</i></p>
                    <div class="incident-inner">
                        <b>Regulatory Mapping:</b> <span style="color:#38bdf8;">{comp_mapping}</span><br>
                        <b>MITRE ATT&CK:</b> <span style="color:#fbbf24;">{mitre_technique}</span><br>
                        <b>Remediation Playbook:</b> <span style="color:#34d399;">{remediation}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.success("Continuous monitoring registry indicates 100% compliant alignment.")

# === 8. ENGINE VALIDATION SCORECARD ===
elif active_tab == "Engine Validation Scorecard":
    st.subheader("Automated Scorecard Verification")
    st.caption("Automated metrics comparing engine runtime logic classifications against simulated ground truth boundaries.")
    st.markdown("---")
    
    from sklearn.metrics import precision_score, recall_score
    
    y_true = df['is_risky'].astype(int)
    y_pred = df['predicted_risky'].astype(int)
    
    precision = precision_score(y_true, y_pred, zero_division=0) * 100
    recall = recall_score(y_true, y_pred, zero_division=0) * 100
    
    critical_mask = df['severity'] == 'CRITICAL'
    crit_recall = recall_score(y_true[critical_mask], y_pred[critical_mask], zero_division=0) * 100 if critical_mask.sum() > 0 else 100
    
    benign_mask = df['is_risky'] == False
    suppression_rate = (1 - df[benign_mask]['predicted_risky'].mean()) * 100 if benign_mask.sum() > 0 else 100
    
    v1, v2, v3, v4 = st.columns(4)
    v1.metric("Engine Precision Score", f"{precision:.1f}%", "Target: >75%")
    v2.metric("Engine Recall Score", f"{recall:.1f}%", "Target: >70%")
    v3.metric("Critical Anomaly Recall", f"{crit_recall:.1f}%", "Target: >95%")
    v4.metric("Benign Noise Suppression", f"{suppression_rate:.1f}%", "Target: >85%")
    
    st.markdown("---")
    st.markdown("### Live System Validation Status Matrix")
    
    st.checkbox("Pass: Model Precision meets evaluation expectations (>75%)", value=(precision >= 75), disabled=True)
    st.checkbox("Pass: System Catch Recall captures data risks (>70%)", value=(recall >= 70), disabled=True)
    st.checkbox("Pass: High-Severity Critical vectors fully covered (>95%)", value=(crit_recall >= 95), disabled=True)
    st.checkbox("Pass: Devops Operations alert dampening working correctly (>85%)", value=(suppression_rate >= 85), disabled=True)