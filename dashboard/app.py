import streamlit as st  # type: ignore
import pandas as pd  # type: ignore
import json
from pathlib import Path
import plotly.express as px  # type: ignore

# Page Config
st.set_page_config(
    page_title="AEGIS Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for "Professional Security" look
st.markdown("""
<style>
    /* Global Theme */
    .stApp {
        background-color: #0E1117;
        color: #E0E0E0;
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #FAFAFA !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px;
    }
    
    h1 { font-size: 2.2rem !important; }
    h2 { font-size: 1.5rem !important; border-bottom: 1px solid #303030; padding-bottom: 10px; margin-top: 20px;}
    h3 { font-size: 1.2rem !important; color: #A0A0A0 !important; }

    /* Cards/Metrics */
    div[data-testid="stMetricValue"] {
        font-family: 'Source Code Pro', monospace;
        font-size: 28px !important;
        color: #00FF41 !important; /* Cyber Green */
    }
    div[data-testid="stMetricLabel"] {
        color: #888888 !important;
        font-size: 14px !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #161B22;
        border-right: 1px solid #30363D;
    }
    
    /* Tables/JSON */
    .stJson {
        background-color: #0D1117;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 10px;
    }

    /* Status Indicators */
    .status-blocked {
        color: #FF7B72;
        font-weight: bold;
        border-left: 3px solid #FF7B72;
        padding-left: 8px;
    }
    .status-allowed {
        color: #238636;
        font-weight: bold;
        border-left: 3px solid #238636;
        padding-left: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.title("AEGIS SECURITY COMMAND CENTER")
st.markdown("### AUTOMATED AGENT EVALUATION SYSTEM")
st.markdown("---")

# Load Runs
RUNS_DIR = Path("runs")
if not RUNS_DIR.exists():
    st.error("No run data found. Initialize benchmark execution to generate telemetry.")
    st.stop()

runs = sorted([d for d in RUNS_DIR.iterdir() if d.is_dir()], reverse=True)
run_opts = [r.name for r in runs]

if not run_opts:
    st.warning("Runs directory is empty.")
    st.stop()

with st.sidebar:
    st.header("CONFIGURATION")
    selected_run_id = st.selectbox("TRACE ID", run_opts)
    
    st.markdown("---")
    st.markdown("**SYSTEM STATUS**")
    st.info("ACTIVE MONITORING")

run_path = RUNS_DIR / selected_run_id
trace_file = run_path / "trace.jsonl"

if not trace_file.exists():
    st.error(f"Trace file missing for ID: {selected_run_id}")
    st.stop()

# Load Data
data = []
with open(trace_file, "r") as f:
    for line in f:
        data.append(json.loads(line))

df = pd.DataFrame(data)

# Metrics Processing
total_events = len(df)
if "kind" in df.columns:
    approvals = df[df["kind"] == "tool_decision"].copy()
else:
    approvals = pd.DataFrame()

allowed_count = 0
blocked_count = 0

if not approvals.empty:
    approvals["allowed"] = approvals["allowed"].fillna(False).astype(bool)
    blocked_count = len(approvals[~approvals["allowed"]])
    allowed_count = len(approvals[approvals["allowed"]])

# KPI Row
col1, col2, col3 = st.columns(3)
col1.metric("TOTAL EVENTS", total_events)
col2.metric("ACTIONS ALLOWED", allowed_count)
col3.metric("ACTIONS BLOCKED", blocked_count)

st.markdown("---")

# Analytics Section
st.header("SECURITY ANALYTICS")
c1, c2 = st.columns(2)

with c1:
    if not approvals.empty:
        status_counts = approvals["allowed"].map({False: "BLOCKED", True: "ALLOWED"}).value_counts()
        fig = px.pie(
            names=status_counts.index, 
            values=status_counts.values,
            color=status_counts.index,
            color_discrete_map={"BLOCKED": "#DA3633", "ALLOWED": "#238636"},
            hole=0.6,
        )
        fig.update_layout(
            title_text="POLICY ENFORCEMENT",
            title_font_color="#FAFAFA",
            paper_bgcolor="rgba(0,0,0,0)", 
            plot_bgcolor="rgba(0,0,0,0)", 
            font_color="#A0A0A0",
            showlegend=True,
            margin={"t": 40, "b": 0, "l": 0, "r": 0}
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No policy decisions recorded in this trace.")

with c2:
    if "kind" in df.columns:
        event_counts = df["kind"].value_counts().reset_index()
        event_counts.columns = ["Event Type", "Count"]
        
        fig2 = px.bar(
            event_counts,
            x="Event Type", 
            y="Count",
            color="Event Type",
            color_discrete_sequence=px.colors.qualitative.Dark24
        )
        fig2.update_layout(
            title_text="EVENT DISTRIBUTION",
            title_font_color="#FAFAFA",
            paper_bgcolor="rgba(0,0,0,0)", 
            plot_bgcolor="rgba(0,0,0,0)", 
            font_color="#A0A0A0",
            xaxis={"showgrid": False},
            yaxis={"showgrid": True, "gridcolor": "#30363D"},
            margin={"t": 40, "b": 0, "l": 0, "r": 0},
            showlegend=False
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No event data available.")

# Trace Log Section
st.header("INCIDENT TRACE LOG")

# Filters
col_filter, _ = st.columns([1, 2])
with col_filter:
    filter_blocked = st.checkbox("Show only BLOCKED actions", value=False)

st.markdown("<br>", unsafe_allow_html=True)

for event in data:
    kind = event.get("kind")
    
    if kind == "tool_decision":
        is_blocked = not event.get("allowed")
        
        if filter_blocked and not is_blocked:
            continue
            
        status_color = "#DA3633" if is_blocked else "#238636"
        status_text = "BLOCKED" if is_blocked else "ALLOWED"
        
        with st.expander(f"{status_text}: {event.get('tool_name', 'Unknown Tool')}", expanded=is_blocked):
            c_a, c_b = st.columns([1, 3])
            
            with c_a:
                st.markdown("**STATUS**")
                st.markdown(f"<div style='color:{status_color}; font-weight:bold; border:1px solid {status_color}; padding:5px; text-align:center; border-radius:4px;'>{status_text}</div>", unsafe_allow_html=True)
                
            with c_b:
                st.markdown("**REASONING**")
                st.write(event.get('reason', 'N/A'))
            
            st.markdown("**ARGUMENTS**")
            st.json(event.get("args", {}))
    
    elif kind == "run_start":
        st.markdown(f"<div style='color:#888; font-size:12px; margin: 10px 0;'>System initialized at {event.get('ts')}</div>", unsafe_allow_html=True)
