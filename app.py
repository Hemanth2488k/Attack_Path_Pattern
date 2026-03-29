# app.py
import streamlit as st
import subprocess
import json
import os
import pandas as pd
import time
import base64
from pathlib import Path

import sys
from pathlib import Path

# Add this near the top (after imports)
VENV_PYTHON = str(Path(sys.executable).resolve())  # Full path to .venv python
# ----------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data" / "gnn"
GRAPH_JSON = DATA_DIR / "bipartite_attack_graph.json"
HTML_GRAPH = PROJECT_ROOT / "attack_graph.html"
EXPLANATIONS_JSON = DATA_DIR / "explanations.json"
GEMINI_JSON = DATA_DIR / "gemini_output.json"
# Make sure output folders exist
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def run_script(script_name: str, args: list = None) -> tuple[bool, str]:
    """Run script using the SAME .venv Python interpreter."""
    cmd = [VENV_PYTHON, script_name]
    if args:
        cmd.extend(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=600
        )
        out = result.stdout + "\n" + result.stderr
        return (result.returncode == 0, out)
    except subprocess.TimeoutExpired:
        return (False, "Timeout while running " + script_name)

def load_graph_summary() -> pd.DataFrame:
    """Read the JSON graph and return a host-centric dataframe."""
    if not GRAPH_JSON.exists():
        return pd.DataFrame()
    with open(GRAPH_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for nid, meta in data.get("nodes", {}).items():
        if meta.get("node_type") in ("ip_address", "host"):
            # Extract service names only
            services_list = meta.get("services", [])
            service_names = []
            if isinstance(services_list, list):
                for svc in services_list:
                    if isinstance(svc, dict):
                        name = svc.get("service", "")
                        product = svc.get("product", "")
                        version = svc.get("version", "")
                        parts = [p for p in (name, product, version) if p]
                        service_names.append(" ".join(parts))
                    else:
                        service_names.append(str(svc))
            else:
                service_names = [str(services_list)]

            rows.append(
                {
                    "IP": nid,
                    "Ports": len(meta.get("open_ports", [])),
                    "Services": ", ".join(service_names),
                    "Vulns": len(meta.get("cves", [])),
                    "Risk": round(meta.get("risk", 0.0), 3),
                }
            )
    return pd.DataFrame(rows).sort_values("Risk", ascending=False)


def load_explanations() -> list:
    """Load Gemini explanations (list of dicts)."""
    if not EXPLANATIONS_JSON.exists():
        return []
    with open(EXPLANATIONS_JSON, "r") as f:
        return json.load(f)


def graph_to_base64() -> str:
    """Convert the HTML graph to a base64 string for PDF download."""
    if not HTML_GRAPH.exists():
        return ""
    with open(HTML_GRAPH, "rb") as f:
        return base64.b64encode(f.read()).decode()
def display_gemini_explanations():
    """Load and display Gemini output in expandable format."""
    gemini_path = DATA_DIR / "gemini_output.json"
    if not gemini_path.exists():
        st.info("No Gemini explanations generated yet (run the pipeline with a valid API key).")
        return
    
    try:
        with open(gemini_path, "r", encoding="utf-8") as f:
            expl = json.load(f)
        
        if not expl:  # Empty list
            st.info("Gemini output is empty.")
            return
        
        st.subheader("Gemini Explanations")
        for item in expl:
            path_str = item.get('path', 'Unknown Path')
            score = item.get('score', 0)
            with st.expander(f"Path: {path_str} (Score: {score:.3f})"):
                st.markdown(f"**Explanation:** {item.get('short_explanation', '—')}")
                if 'top_remediations' in item and item['top_remediations']:
                    st.markdown("**Remediations:**")
                    for r in item['top_remediations']:
                        st.markdown(f"- {r}")
                st.markdown(f"*Priority Reason:* {item.get('priority_reason', '—')}")
                
    except json.JSONDecodeError:
        st.error("Invalid JSON in gemini_output.json – check the file.")
    except Exception as e:
        st.error(f"Error loading Gemini output: {e}")

# ----------------------------------------------------------------------
# Streamlit UI
# ----------------------------------------------------------------------
st.set_page_config(page_title="Attack Path Planner", layout="wide")
st.title("Context-Aware Attack Path Planner")
st.markdown(
    """
*Scan a subnet → Build a bipartite attack graph → GATv2 risk prediction → Gemini explanations.*  
"""
)

# Global progress bar — visible on ALL tabs, right below the title
progress_bar = st.progress(0)

# ----------------------------------------------------------------------
# Main Content Tabs
# ----------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(["Status", "Nmap Results", "Attack Graph", "Gemini Explanations"])

with tab1:
    st.subheader("Pipeline Status")
    
    # Placeholder for live-updating status log
    status_placeholder = st.empty()
    
    # Session state to persist log across reruns
    if "log_lines" not in st.session_state:
        st.session_state.log_lines = []

    def update_status(message):
        st.session_state.log_lines.append(message)
        status_placeholder.info("\n".join(st.session_state.log_lines))

    # Sidebar controls (only visible in Status tab, as requested)
    with st.sidebar:
        st.header("Attack Path Planner")
        
        uploaded_file = st.file_uploader(
            "Upload `bipartite_attack_graph.json` (optional)",
            type=["json"]
        )
        
        run_btn = st.button("Run Full Pipeline", type="primary")
        
        st.markdown("---")
        st.caption("""
        **How it works:**  
        • No file → Auto-scan local network (`new.py`)  
        • With file → Use uploaded graph  
        • Gemini explanations → Built-in  
        """)

    if run_btn:
        with st.spinner("Running pipeline..."):
            # Reset log and start
            st.session_state.log_lines = []
            update_status("Starting pipeline...")

            if uploaded_file:
                progress_bar.progress(10)
                update_status("\nUsing uploaded graph file...")
                content = uploaded_file.read()
                GRAPH_JSON.write_bytes(content)
                update_status("\nUploaded graph loaded successfully")
                progress_bar.progress(40)
            else:
                progress_bar.progress(10)
                update_status("\nGetting local subnet...")
                time.sleep(0.5)

                update_status("\nIdentifying active hosts...")
                ok, out = run_script("new.py")
                if not ok:
                    update_status("\nScanning failed")
                    st.error("`new.py` failed. Check terminal for details.")
                    st.code(out)
                    st.stop()
                update_status("\nActive hosts identified")
                time.sleep(0.5)

                update_status("\nScanning open ports and services...")
                time.sleep(0.5)
                update_status("\nPort scanning complete")
                progress_bar.progress(30)
                update_status("\nBuilding bipartite attack graph...")
                time.sleep(0.5)
                update_status("\nGraph built and saved")

            progress_bar.progress(60)
            update_status("\nLoading GATv2 model and predicting risks...")
            update_status("\nRanking attack paths...")
            time.sleep(0.5)
            update_status("\nGenerating explanations with Gemini...")

            ok, out = run_script("gat_gemini.py", args=["--json", str(GRAPH_JSON)])
            if not ok:
                update_status("\nAnalysis failed")
                st.error("`gat_gemini.py` failed.")
                st.code(out)
                st.stop()

            update_status("\nRisk prediction and path ranking complete")
            progress_bar.progress(90)

            if GEMINI_JSON.exists():
                update_status("\nGemini explanations generated")
            else:
                update_status("\nGemini explanations skipped (no API key or rate limit)")

            progress_bar.progress(100)
            update_status("\nPipeline finished successfully!")

with tab2:
    st.subheader("Nmap Results & Host Summary")
    if GRAPH_JSON.exists():
        df = load_graph_summary()  # Use your existing function
        if not df.empty:
            st.dataframe(df.style.highlight_max(subset=["Risk"], color="#ff4d4d"))
        else:
            st.info("No hosts found in graph.")
    else:
        st.info("Run the pipeline to see Nmap results.")

with tab3:
    st.subheader("Interactive Attack Graph")
    if HTML_GRAPH.exists():
        with open(HTML_GRAPH, "r", encoding="utf-8") as f:
            html_content = f.read()

        # Embed the graph directly in Streamlit
        st.components.v1.html(html_content, height=800, scrolling=True)

        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            with open(GRAPH_JSON, "rb") as f:
                st.download_button(
                    "Download Graph JSON",
                    f,
                    file_name="bipartite_attack_graph.json",
                    mime="application/json"
                )
        with col2:
            # Button to open full graph in new tab
            with open(HTML_GRAPH, "rb") as f:
                html_bytes = f.read()
            b64 = base64.b64encode(html_bytes).decode()
            href = f'<a href="data:text/html;base64,{b64}" target="_blank">Open Full Interactive Graph in New Tab</a>'
            st.markdown(href, unsafe_allow_html=True)

        # Alternative: Direct download of HTML
        st.download_button(
            "Download Graph as HTML",
            html_bytes,
            file_name="attack_graph.html",
            mime="text/html"
        )
    else:
        st.info("Run the pipeline to generate the attack graph.")

with tab4:
    st.subheader("Gemini Explanations")
    if GEMINI_JSON.exists():
        try:
            with open(GEMINI_JSON, "r", encoding="utf-8") as f:
                explanations = json.load(f)
            if explanations:
                for item in explanations:
                    path = item.get("path", "Unknown")
                    score = item.get("score", 0)
                    with st.expander(f"Path: {path} (Score: {score:.3f})"):
                        st.markdown(f"**Explanation:** {item.get('short_explanation', '—')}")
                        remeds = item.get("top_remediations", [])
                        if remeds:
                            st.markdown("**Recommended Remediations:**")
                            for r in remeds:
                                st.markdown(f"- {r}")
                        st.markdown(f"*Priority Reason:* {item.get('priority_reason', '—')}")
            else:
                st.info("Gemini returned empty results.")
        except Exception as e:
            st.error(f"Error reading Gemini output: {e}")
    else:
        st.info("No Gemini explanations available. Run the pipeline with a valid API key.")

# ----------------------------------------------------------------------
# Footer
# ----------------------------------------------------------------------
st.caption("Built with **Streamlit** | Backend: `new.py` + `gat_gemini.py`")
