import networkx as nx
import pandas as pd
from typing import Tuple, Dict, Any, List

def build_attack_graph(events_df: pd.DataFrame) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Constructs a directed Kill-Chain graph modeling relationships between
    Actors, Compromised Baseline Controls, Asset Targets, and Domains.
    """
    G = nx.DiGraph()
    if "predicted_risky" in events_df.columns:
        risky_events = events_df[events_df["predicted_risky"] == 1]
    else:
        risky_events = events_df

    impacted_domains = set()
    impacted_assets = set()
    actors = set()

    for _, row in risky_events.iterrows():
        actor = str(row.get("changed_by", "unknown-actor"))
        cid = str(row.get("control_id", "unknown-control"))
        asset = str(row.get("asset_target", "unknown-asset"))
        domain = str(row.get("domain", "unknown-domain"))
        severity = str(row.get("severity", "MEDIUM"))
        seq_cat = row.get("sequence_category") or "drift"
        
        actors.add(actor)
        impacted_domains.add(domain)
        impacted_assets.add(asset)

        # Node attributes
        G.add_node(actor, node_type="actor", label=actor, color="#f43f5e", size=24)
        G.add_node(cid, node_type="control", label=cid, severity=severity, color="#fbbf24", size=20)
        G.add_node(asset, node_type="asset", label=asset, color="#38bdf8", size=22)
        G.add_node(domain, node_type="domain", label=domain, color="#a855f7", size=26)

        # Edges showing progression / association
        G.add_edge(actor, cid, relationship="manipulated", category=str(seq_cat))
        G.add_edge(cid, asset, relationship="protects")
        G.add_edge(asset, domain, relationship="resides_in")

    stats = {
        "active_threat_nodes": G.number_of_nodes(),
        "attack_paths": G.number_of_edges(),
        "actors": sorted(list(actors)),
        "impacted_domains": sorted(list(impacted_domains)),
        "impacted_assets": sorted(list(impacted_assets))
    }
    return G, stats

def calculate_blast_radius(
    num_compromised_controls: int,
    num_domains: int,
    has_critical: bool,
    has_production: bool
) -> Tuple[float, List[str]]:
    """
    Evaluates blast radius score (0 - 100) based on domain spread,
    asset environment criticality, and breached control severity.
    """
    factors = []
    score = 15.0 # baseline base drift score
    
    control_weight = min(35.0, num_compromised_controls * 7.0)
    score += control_weight
    factors.append(f"{num_compromised_controls} compromised controls (+{control_weight:.1f})")

    domain_weight = min(25.0, num_domains * 10.0)
    score += domain_weight
    factors.append(f"{num_domains} impacted infrastructure domains (+{domain_weight:.1f})")

    if has_critical:
        score += 15.0
        factors.append("CRITICAL severity controls breached (+15.0)")
    if has_production:
        score += 10.0
        factors.append("Direct production environment target (+10.0)")

    final_score = round(min(100.0, max(0.0, score)), 1)
    return final_score, factors

def get_plotly_network_figure(G: nx.DiGraph, theme: str = "dark"):
    """
    Generates an interactive Plotly graph visualizing nodes and kill-chain vectors,
    adapted for both dark and light modes.
    """
    import plotly.graph_objects as go
    is_light = (theme.lower() == "light")
    bg_color = "#ffffff" if is_light else "#111827"
    text_color = "#0f172a" if is_light else "#f9fafb"
    edge_color = "rgba(100, 116, 139, 0.45)" if is_light else "rgba(156, 163, 175, 0.35)"
    marker_border = "#e2e8f0" if is_light else "#ffffff"

    if G.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor=bg_color,
            plot_bgcolor=bg_color,
            annotations=[dict(text="No Active Threat Graph Nodes to Display", showarrow=False, font=dict(color="#64748b" if is_light else "#9ca3af", size=16))]
        )
        return fig

    # Compute spring layout
    pos = nx.spring_layout(G, seed=42, k=0.9, iterations=50)
    
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color=edge_color),
        hoverinfo="none",
        mode="lines"
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    node_labels = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        data = G.nodes[node]
        ntype = data.get("node_type", "entity").upper()
        deg = G.degree(node)
        node_text.append(f"<b>[{ntype}]</b> {node}<br>Relationships: {deg}")
        
        # Avoid label overcrowding: only label major domain hubs, actors, and high-connectivity nodes
        if ntype in ("DOMAIN", "ACTOR") or deg >= 4:
            node_labels.append(str(node))
        else:
            node_labels.append("")

        node_color.append(data.get("color", "#38bdf8"))
        node_size.append(data.get("size", 20))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=node_labels,
        textposition="top center",
        hoverinfo="text",
        hovertext=node_text,
        textfont=dict(size=12, color=text_color),
        marker=dict(
            size=node_size,
            color=node_color,
            line=dict(width=2, color=marker_border)
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(
                text="<b>Cross-Domain Lateral Movement & Threat Topology</b>",
                font=dict(color=text_color, size=18)
            ),
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=20, r=20, t=50),
            paper_bgcolor=bg_color,
            plot_bgcolor=bg_color,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
    )
    return fig
