"""
=============================================================================
BACHAO+ | Defence & Security Platform
Tagline: Your Safety. Our Priority.
Category: Defence and Security
=============================================================================
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Database and Core Engine
from database.db import (
    init_db,
    seed_demo_data_if_empty,
    get_dashboard_metrics,
    get_recent_events,
    get_incident_status_distribution,
    get_threat_distribution
)

# Feature Modules
from modules.phishing import render_phishing_page
from modules.password_safety import render_password_safety_page
from modules.campus_safety import render_campus_safety_page
from modules.secure_access import render_secure_access_page

# ---------------------------------------------------------------------------
# Streamlit Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="BACHAO+ | Defence & Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database Schema & Seed Baseline Records
seed_demo_data_if_empty()

# Initialize Navigation Session State
if "nav_selection" not in st.session_state:
    st.session_state["nav_selection"] = "📊 Dashboard"

# ---------------------------------------------------------------------------
# Sophisticated Cream & Tactical Navy Theme Styling
# ---------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    :root {
        --bg-cream-main: #F9F6F0;
        --bg-cream-card: #FFFFFF;
        --bg-sidebar: #F2ECE1;
        --border-cream: #E5DCCE;
        --border-card: #E8E0D2;
        --text-slate-main: #0F172A;
        --text-slate-muted: #526071;
        --brand-amber: #B45309;
        --brand-gold: #D97706;
        --brand-teal: #0F766E;
        --brand-red: #DC2626;
        --brand-green-subtle: #15803D;
    }

    /* Base Body Background */
    .stApp {
        background-color: var(--bg-cream-main);
        font-family: 'Plus Jakarta Sans', sans-serif;
        color: var(--text-slate-main);
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: var(--bg-sidebar);
        border-right: 1px solid var(--border-cream);
    }
    
    section[data-testid="stSidebar"] h1, 
    section[data-testid="stSidebar"] h2, 
    section[data-testid="stSidebar"] h3 {
        color: var(--text-slate-main);
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    /* Brand Header Box */
    .brand-banner {
        background: linear-gradient(135deg, #FAF7F2 0%, #EFE7DA 100%);
        border: 1px solid var(--border-cream);
        border-radius: 12px;
        padding: 24px 28px;
        margin-bottom: 22px;
        box-shadow: 0 4px 14px rgba(180, 83, 9, 0.04);
    }

    .brand-title {
        font-size: 2.3rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #0F172A;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .brand-title span.plus {
        color: #B45309;
    }

    .brand-tagline {
        color: #B45309;
        font-weight: 700;
        font-size: 1.05rem;
        margin-top: 4px;
        margin-bottom: 4px;
        letter-spacing: 0.2px;
    }

    .brand-subtext {
        color: var(--text-slate-muted);
        font-size: 0.95rem;
        margin-top: 2px;
        margin-bottom: 0;
    }

    /* Module Page Headers */
    .module-header {
        background: #FFFFFF;
        border: 1px solid var(--border-card);
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 20px;
        border-left: 5px solid #B45309;
    }
    .module-header h2 {
        margin: 0;
        font-size: 1.6rem;
        color: #0F172A;
    }
    .module-header p.subtitle {
        color: #64748B;
        margin: 4px 0 0 0;
        font-size: 0.95rem;
    }

    /* Metric Cards */
    .metric-card {
        background: var(--bg-cream-card);
        border: 1px solid var(--border-card);
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.02);
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 14px rgba(180, 83, 9, 0.07);
    }
    .metric-label {
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #64748B;
    }
    .metric-value {
        font-size: 2.0rem;
        font-weight: 800;
        color: #0F172A;
        font-family: 'JetBrains Mono', monospace;
        margin: 4px 0;
    }
    .metric-sub {
        font-size: 0.82rem;
        color: #0F766E;
        font-weight: 600;
    }

    /* Action Cards */
    .action-card {
        background: #FFFFFF;
        border: 1px solid var(--border-cream);
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 12px;
        transition: all 0.2s ease;
        box-shadow: 0 2px 5px rgba(0,0,0,0.02);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .action-card:hover {
        border-color: #B45309;
        box-shadow: 0 4px 12px rgba(180, 83, 9, 0.08);
    }
    .action-card h4 {
        margin: 0 0 6px 0;
        color: #0F172A;
        font-size: 1.1rem;
    }
    .action-card p {
        color: #526071;
        font-size: 0.88rem;
        margin: 0 0 12px 0;
    }

    /* Info Boxes */
    .info-box {
        background: #FFFFFF;
        border: 1px solid #E5DCCE;
        border-radius: 10px;
        padding: 18px;
    }
    .info-box h4 {
        margin-top: 0;
        color: #B45309;
        font-size: 1.05rem;
    }

    /* Sidebar Status Badge */
    .defense-badge {
        background-color: #EFE7DA;
        border: 1px solid #D6C7B2;
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 700;
        color: #78350F;
        display: inline-block;
        margin-bottom: 15px;
    }

    /* Form and Button Styling */
    div[data-testid="stTextInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stSelectbox"] > div {
        background-color: #FFFFFF !important;
        border: 1px solid #D6C7B2 !important;
        border-radius: 6px !important;
        color: #0F172A !important;
    }

    div[data-testid="stButton"] button {
        background: #B45309;
        color: #FFFFFF;
        border: 1px solid #92400E;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s;
    }
    div[data-testid="stButton"] button:hover {
        background: #92400E;
        border-color: #78350F;
        color: #FFFFFF;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar Navigation & Authentication Session Header
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
        <div style="padding: 10px 0 8px 0;">
            <div style="font-size: 1.6rem; font-weight: 800; color: #0F172A; display: flex; align-items: center; gap: 8px;">
                🛡️ BACHAO<span style="color: #B45309;">+</span>
            </div>
            <div style="font-size: 0.8rem; color: #B45309; font-weight: 700; margin-top: 2px;">
                Your Safety. Our Priority.
            </div>
            <div style="font-size: 0.75rem; color: #64748B; font-weight: 600;">
                Category: Defence & Security
            </div>
        </div>
        <div class="defense-badge">🟢 DEFCON 5: ALL SYSTEMS NOMINAL</div>
    """, unsafe_allow_html=True)

    # Active User Status Pill in Sidebar
    is_auth = st.session_state.get("authenticated", False)
    logged_user = st.session_state.get("username", "Guest User")
    logged_role = st.session_state.get("role", "Unauthenticated")

    role_badge_color = "#DC2626" if logged_role == "Admin" else ("#B45309" if logged_role == "Campus Security" else "#0F766E")

    if is_auth:
        st.markdown(f"""
            <div style="background: #FFFFFF; border: 1px solid #E5DCCE; border-radius: 6px; padding: 10px 12px; margin-bottom: 16px;">
                <div style="font-size: 0.75rem; color: #64748B; font-weight: 600;">CURRENT SESSION</div>
                <div style="font-weight: 800; color: #0F172A; font-size: 0.95rem;">{logged_user}</div>
                <span style="background: {role_badge_color}18; color: {role_badge_color}; padding: 2px 8px; border-radius: 12px; font-weight: 700; font-size: 0.72rem;">
                    {logged_role.upper()}
                </span>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <div style="background: #FAF7F2; border: 1px dashed #D6C7B2; border-radius: 6px; padding: 10px 12px; margin-bottom: 16px;">
                <div style="font-size: 0.75rem; color: #64748B; font-weight: 600;">SESSION STATUS</div>
                <div style="font-size: 0.85rem; color: #334155; font-weight: 700;">Unauthenticated (Guest Mode)</div>
                <div style="font-size: 0.75rem; color: #94A3B8;">Log in under 'Secure Access' for full permissions.</div>
            </div>
        """, unsafe_allow_html=True)

    # Sidebar Navigation Menu Options
    nav_options = [
        "📊 Dashboard",
        "🎣 Phishing & Scam Detection",
        "🔑 Password Safety",
        "🏫 Campus Safety",
        "🔒 Secure Access"
    ]

    # Ensure current nav selection is valid
    if st.session_state["nav_selection"] not in nav_options:
        st.session_state["nav_selection"] = "📊 Dashboard"

    current_idx = nav_options.index(st.session_state["nav_selection"])

    nav_selection = st.radio(
        "Platform Navigation",
        nav_options,
        index=current_idx,
        key="sidebar_nav_radio",
        label_visibility="collapsed"
    )
    st.session_state["nav_selection"] = nav_selection

    st.markdown("---")
    st.markdown("""
        <div style="font-size: 0.8rem; color: #64748B; line-height: 1.5;">
            <div><strong>Storage:</strong> SQLite Local Engine</div>
            <div><strong>Encryption:</strong> PBKDF2-HMAC-SHA256</div>
            <div><strong>Breach API:</strong> k-Anonymity HIBP</div>
            <div style="margin-top: 8px; color: #94A3B8; font-size: 0.73rem;">
                BACHAO+ Defence MVP • v1.0.0
            </div>
        </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Central Mission Dashboard Renderer
# ---------------------------------------------------------------------------
def render_dashboard() -> None:
    """Render the central mission dashboard with telemetry and visualizations."""
    # Brand Header Banner with Tagline
    st.markdown("""
        <div class="brand-banner">
            <h1 class="brand-title">🛡️ BACHAO<span class="plus">+</span> Mission Command Center</h1>
            <div class="brand-tagline">Your Safety. Our Priority.</div>
            <p class="brand-subtext">Unified Defence & Security Overwatch • Automated Phishing Heuristics • Campus Threat Dispatch • Identity Verification</p>
        </div>
    """, unsafe_allow_html=True)

    # Hackathon Demo Walkthrough Guide (Judges Guide)
    with st.expander("🎯 8-Step Hackathon Demonstration Guide (Click to expand)"):
        st.markdown("""
        **Follow this coherent workflow to test all platform capabilities:**
        1. **Register & Log In as Student**: Go to **Secure Access** tab -> Register a new student account (e.g. `cadet_sharma`) and log in.
        2. **Analyse Suspicious Phishing URL**: Navigate to **Phishing & Scam Detection** -> Click *"Brand Spoofing Link"* -> Run Analysis. Observe the heuristic breakdown and risk score.
        3. **Analyse Social Engineering Message**: Switch to *Email & Message Body Analyzer* -> Click *"Load Sample Phishing Email Demo"* -> Notice the detected psychological urgency coercion markers.
        4. **Check Password Safely**: Open **Password Safety** -> Click *"Leaked: P@ssword1"* -> Run Audit. See the k-anonymity breach count without plaintext transmission.
        5. **Submit Campus Safety Incident**: Go to **Campus Safety** -> Submit an incident report (or trigger Emergency SOS) with an optional photo. Check the *My Reported Incidents* tab to track it.
        6. **Log In as Campus Officer**: Go to **Secure Access** -> Log out -> Register as `Campus Security` using Clearance Key `CAMPUS-SEC-2026` -> Log in.
        7. **Review & Update Incident**: Return to **Campus Safety** -> Open *Security Officer Terminal* -> Update incident from `Submitted` to `In Progress` or `Resolved` with remarks.
        8. **Verify Central Telemetry**: Return to this **Dashboard** to see live updated metrics, charts, and audit stream reflecting your actions!
        """)

    # Fetch Real SQLite Telemetry Metrics (No Fabricated Data)
    metrics = get_dashboard_metrics()

    # Top Metric Counter Cards
    m_c1, m_c2, m_c3, m_c4, m_c5, m_c6 = st.columns(6)
    with m_c1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Total Users</div>
                <div class="metric-value">{metrics['total_users']}</div>
                <div class="metric-sub">Registered Operators</div>
            </div>
        """, unsafe_allow_html=True)
    with m_c2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">URLs Analyzed</div>
                <div class="metric-value">{metrics['urls_analyzed']}</div>
                <div class="metric-sub">Diagnostic Scans</div>
            </div>
        """, unsafe_allow_html=True)
    with m_c3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">High-Risk Threats</div>
                <div class="metric-value" style="color: #DC2626;">{metrics['high_risk_threats']}</div>
                <div class="metric-sub" style="color: #DC2626;">Flagged Deceptions</div>
            </div>
        """, unsafe_allow_html=True)
    with m_c4:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Breach Matches</div>
                <div class="metric-value" style="color: #B45309;">{metrics['pwned_matches']}</div>
                <div class="metric-sub">Compromised Hashes</div>
            </div>
        """, unsafe_allow_html=True)
    with m_c5:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Campus Incidents</div>
                <div class="metric-value">{metrics['incidents_reported']}</div>
                <div class="metric-sub">Total Dispatches</div>
            </div>
        """, unsafe_allow_html=True)
    with m_c6:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Resolved Incidents</div>
                <div class="metric-value" style="color: #0F766E;">{metrics['incidents_resolved']}</div>
                <div class="metric-sub" style="color: #0F766E;">Case Closed</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Plotly Charts Section
    col_chart1, col_chart2 = st.columns([1, 1])

    with col_chart1:
        st.markdown("### 📈 Threat Level Distribution (Phishing & Scams)")
        threat_dist = get_threat_distribution()
        labels = list(threat_dist.keys())
        values = list(threat_dist.values())

        if sum(values) > 0:
            colors = ['#0F766E', '#D97706', '#EA580C', '#DC2626']
            fig_threat = go.Figure(data=[
                go.Bar(
                    x=labels,
                    y=values,
                    marker=dict(color=colors, line=dict(color='#854D0E', width=1)),
                    text=values,
                    textposition='auto'
                )
            ])
            fig_threat.update_layout(
                paper_bgcolor='#FFFFFF',
                plot_bgcolor='#FAF8F4',
                margin=dict(l=20, r=20, t=25, b=20),
                height=260,
                xaxis=dict(title="Risk Classification", tickfont=dict(color='#0F172A', size=11)),
                yaxis=dict(showgrid=True, gridcolor='#E8DFD0', title="Scans Recorded", tickfont=dict(color='#64748B')),
                font=dict(family="Plus Jakarta Sans, sans-serif")
            )
            st.plotly_chart(fig_threat, use_container_width=True)
        else:
            st.info("No phishing scans logged yet. Analyze candidate links in the Phishing Detection module to populate real telemetry.")

    with col_chart2:
        st.markdown("### 📊 Campus Incident Status Distribution")
        inc_dist = get_incident_status_distribution()
        inc_labels = list(inc_dist.keys())
        inc_values = list(inc_dist.values())

        if sum(inc_values) > 0:
            pie_colors = ['#DC2626', '#D97706', '#3B82F6', '#0F766E']
            fig_inc = go.Figure(data=[
                go.Pie(
                    labels=inc_labels,
                    values=inc_values,
                    hole=0.45,
                    marker=dict(colors=pie_colors, line=dict(color='#FFFFFF', width=2))
                )
            ])
            fig_inc.update_layout(
                paper_bgcolor='#FFFFFF',
                margin=dict(l=20, r=20, t=25, b=20),
                height=260,
                showlegend=True,
                font=dict(family="Plus Jakarta Sans, sans-serif")
            )
            st.plotly_chart(fig_inc, use_container_width=True)
        else:
            st.info("No campus incidents submitted yet. Use the Campus Safety module to submit an incident or test SOS dispatch.")

    st.markdown("<br>", unsafe_allow_html=True)



    # Real-Time Security Incident Stream (Direct SQLite Audit Query)
    st.markdown("### 📜 Real-Time Central Security Event Stream")
    events = get_recent_events(limit=10)

    if events:
        df_events = pd.DataFrame(events)[["event_id", "timestamp", "category", "event_type", "severity", "user_id", "description"]]
        df_events.columns = ["Event ID", "Timestamp", "Category", "Event Type", "Severity", "Actor", "Description"]
        st.dataframe(df_events, use_container_width=True, hide_index=True)
    else:
        st.info("No security telemetry events registered.")


# ---------------------------------------------------------------------------
# Main Routing Logic
# ---------------------------------------------------------------------------
active_nav = st.session_state.get("nav_selection", "📊 Dashboard")

if active_nav == "📊 Dashboard":
    render_dashboard()
elif active_nav == "🎣 Phishing & Scam Detection":
    render_phishing_page()
elif active_nav == "🔑 Password Safety":
    render_password_safety_page()
elif active_nav == "🏫 Campus Safety":
    render_campus_safety_page()
elif active_nav == "🔒 Secure Access":
    render_secure_access_page()
