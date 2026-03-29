#!/usr/bin/env python3
import os, json, socket, webbrowser, requests, argparse
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
import torch
import torch.nn as nn
import torch.nn.functional as F
import networkx as nx
from torch_geometric.nn import GATv2Conv
from pyvis.network import Network
from neo4j import GraphDatabase
import google.generativeai as genai  
from pathlib import Path
# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
EDGE_WEIGHT_MIN, EDGE_WEIGHT_MAX = 0.1, 1.0
GEMINI_MODEL_PREFERRED = ["gemini-1.5-flash"]
#GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY_PLACEHOLDER", "AIzaSyAk0oG88pIS9Ff0vEsBDXrhNI09vl2Nn3g")
GEMINI_API_KEY=""
# Default Neo4j env
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "password")

# -------------------------------------------------------------------
# MODEL
# -------------------------------------------------------------------
class GATv2Model(nn.Module):
    def __init__(self, in_channels=6, hidden_channels=64, out_channels=1, heads=4):
        super().__init__()
        self.gat1 = GATv2Conv(in_channels, hidden_channels, heads=heads, concat=True)
        self.gat2 = GATv2Conv(hidden_channels * heads, hidden_channels, heads=1, concat=False)
        self.fc = nn.Linear(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        x = F.elu(self.gat1(x, edge_index))
        x = F.elu(self.gat2(x, edge_index))
        return torch.sigmoid(self.fc(x)).squeeze(-1)

# -------------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------------
def resolve_name(ip_or_name):
    try:
        return socket.gethostbyaddr(ip_or_name)[0]
    except Exception:
        return ip_or_name

def risk_color(score):
    if score >= 0.9: return "#ff3333"
    if score >= 0.7: return "#ff9933"
    if score >= 0.4: return "#ffff66"
    return "#88cc88"

# -------------------------------------------------------------------
# GRAPH BUILDING (JSON fallback)
# -------------------------------------------------------------------
def load_graph_from_json(path: str) -> nx.DiGraph:
    with open(path, "r") as f:
        data = json.load(f)
    G = nx.DiGraph()
    for nid, meta in data.get("nodes", {}).items():
        m = dict(meta)
        node_type = (m.get("node_type") or "unknown").lower()
        m["node_type"] = node_type
        feats = m.get("features", [0, 0, 0, 0, 0, 0])
        if len(feats) < 6:
            feats = feats + [0] * (6 - len(feats))
        m["features"] = feats
        G.add_node(nid, **m)
    for e in data.get("edges", []):
        src, dst = e.get("src"), e.get("dst")
        if not src or not dst: continue
        st = (data["nodes"].get(src, {}).get("node_type") or "").lower()
        dt = (data["nodes"].get(dst, {}).get("node_type") or "").lower()
        edge_attrs = {k: v for k, v in e.items() if k not in ("src", "dst")}
        if st in ("ip_address", "host") and dt in ("ip_address", "host"):
            edge_attrs.setdefault("edge_type", "host-host")
        G.add_edge(src, dst, **edge_attrs)
    return G

# -------------------------------------------------------------------
# GRAPH BUILDING (Neo4j loader)
# -------------------------------------------------------------------
def load_graph_from_neo4j(uri, user, password):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    G = nx.DiGraph()
    try:
        with driver.session() as session:
            # Get hosts with numeric properties
            host_q = """
            MATCH (h:Host)
            OPTIONAL MATCH (h)-[r:HAS_VULN]->(v:Vulnerability)
            RETURN DISTINCT h.ip AS ip,
                   h.ports_count AS ports_count,
                   h.vuln_count AS vuln_count,
                   h.cvss_mean AS cvss_mean,
                   h.cvss_max AS cvss_max,
                   h.high_vulns AS high_vulns,
                   h.medium_vulns AS medium_vulns,
                   collect(DISTINCT v.cve) AS vulns
            """
            res = session.run(host_q)
            for rec in res:
                ip = rec["ip"]
                # ensure numeric defaults
                ports_count = int(rec["ports_count"] or 0)
                vuln_count = int(rec["vuln_count"] or 0)
                cvss_mean = float(rec["cvss_mean"] or 0.0)
                cvss_max = float(rec["cvss_max"] or 0.0)
                high_vulns = int(rec["high_vulns"] or 0)
                medium_vulns = int(rec["medium_vulns"] or 0)
                vulns = [v for v in rec["vulns"] if v]

                G.add_node(ip, node_type="ip_address",
                           open_ports_count=ports_count,
                           vuln_count=vuln_count,
                           cvss_mean=cvss_mean,
                           cvss_max=cvss_max,
                           high_vulns=high_vulns,
                           medium_vulns=medium_vulns,
                           features=[ports_count, vuln_count, cvss_mean/10.0, cvss_max/10.0, high_vulns, medium_vulns])
                # add edges host->vulnerability for each vuln present
                for v in vulns:
                    if not v:
                        continue
                    if not G.has_node(v):
                        # fetch cvss property for vulnerability
                        vrec = session.run("MATCH (x:Vulnerability {cve:$c}) RETURN x.cvss AS cvss, x.description AS desc", c=v).single()
                        cvss_val = float(vrec["cvss"] or 0.0) if vrec else 0.0
                        desc = vrec["desc"] if vrec and vrec["desc"] else ""
                        G.add_node(v, node_type="vulnerability", cvss_score=cvss_val, description=desc, features=[cvss_val/10.0, 0,0,0,0,0])
                    G.add_edge(ip, v, edge_type="has_vulnerability", edge_weight=(G.nodes[v].get("cvss_score",0.0)/10.0))

            # Add host-host connectivity edges (if present)
            conn_res = session.run("""
            MATCH (a:Host)-[r:NETWORK_CONNECTIVITY]->(b:Host)
            RETURN a.ip AS src, b.ip AS dst, r.edge_weight AS edge_weight
            """)
            for rec in conn_res:
                src = rec["src"]
                dst = rec["dst"]
                ew = float(rec["edge_weight"] or 1.0)
                if src and dst:
                    # ensure host nodes exist
                    if not G.has_node(src):
                        G.add_node(src, node_type="ip_address", features=[0,0,0,0,0,0])
                    if not G.has_node(dst):
                        G.add_node(dst, node_type="ip_address", features=[0,0,0,0,0,0])
                    G.add_edge(src, dst, edge_type="network_connectivity", edge_weight=ew)

    finally:
        driver.close()
    return G

# -------------------------------------------------------------------
# CONVERT TO TENSORS (same as before)
# -------------------------------------------------------------------
def build_tensors(G):
    nodes = list(G.nodes())
    id2i = {n: i for i, n in enumerate(nodes)}
    feats = [G.nodes[n].get("features", [0]*6) for n in nodes]
    feat_len = max(6, max((len(f) for f in feats), default=6))
    feats = [f + [0]*(feat_len - len(f)) if len(f) < feat_len else f[:feat_len] for f in feats]
    X = torch.tensor(feats, dtype=torch.float32)
    src, dst = [], []
    for u, v in G.edges():
        if u in id2i and v in id2i:
            src.append(id2i[u])
            dst.append(id2i[v])
    edge_index = torch.tensor([src, dst], dtype=torch.long) if src else torch.zeros((2, 0), dtype=torch.long)
    return nodes, X, edge_index

# -------------------------------------------------------------------
# EDGE PROBABILITIES & PATH SCORE (same as before)
# -------------------------------------------------------------------
def categorize_edge_weight(desc: str, service: str, cvss: float) -> float:
    desc, svc = (desc or "").lower(), (service or "").lower()
    base = cvss / 10.0
    if any(k in desc or k in svc for k in ["rce","remote code","overflow","exec","apache","smb","msrpc"]):
        mult = 0.95
    elif any(k in desc or k in svc for k in ["auth","privilege","bypass","ssh","mysql","winrm"]):
        mult = 0.75
    elif any(k in desc or k in svc for k in ["disclosure","dos","xss","csrf","leak"]):
        mult = 0.4
    else:
        mult = 0.5
    return max(min(base * mult * 1.2, EDGE_WEIGHT_MAX), EDGE_WEIGHT_MIN)

def assign_conditional_probs(G: nx.DiGraph):
    for u, v, d in G.edges(data=True):
        tgt = G.nodes[v]
        cvss = float(tgt.get("cvss_score", 0.0))
        desc = d.get("description", tgt.get("description", ""))
        svc = d.get("service", "")
        ew = categorize_edge_weight(desc, svc, cvss)
        trisk = float(tgt.get("risk", cvss / 10.0))
        d["edge_weight"] = ew
        d["attack_prob"] = max(min(ew * trisk, 1.0), 1e-6)

def path_score_conditional(G, path):
    if len(path) < 2: return 0.0
    s = 1.0
    for i in range(len(path)-1):
        if not G.has_edge(path[i], path[i+1]): return 0.0
        s *= float(G.edges[path[i], path[i+1]].get("attack_prob", 1e-6))
    return max(min(s, 1.0), 0.0)

def rank_paths(G, source, top=5, cutoff=6):
    paths = []
    targets = [n for n, d in G.nodes(data=True)
               if d.get("node_type") in ("ip_address","host") and n != source]
    for t in targets:
        try:
            for p in nx.all_simple_paths(G, source=source, target=t, cutoff=cutoff):
                paths.append((p, path_score_conditional(G, p)))
        except: continue
    if not paths: return []
    paths = sorted(paths, key=lambda x: x[1], reverse=True)[:top]
    mn, mx = min(s for _, s in paths), max(s for _, s in paths)
    norm = [(p, (s - mn) / (mx - mn) if mx > mn else 1.0) for p, s in paths]
    return norm

# -------------------------------------------------------------------
# VISUALIZATION 
# -------------------------------------------------------------------
def visualize(G, top_paths, out="attack_graph.html"):
    net = Network(height="900px", width="100%", bgcolor="#0b0b0b", font_color="white", directed=True)
    net.barnes_hut(gravity=-25000, central_gravity=0.3, spring_length=200, spring_strength=0.01)

    hi_nodes = {n for p, _ in top_paths for n in p}
    hi_edges = {(p[i], p[i+1]) for p, _ in top_paths for i in range(len(p)-1)}

    DEFAULT_NODE_SIZE = 18
    HOST_BASE_SIZE = 22
    VULN_BASE_SIZE = 20
    DEFAULT_FONT_SIZE = 34

    for n, d in G.nodes(data=True):
        t = d.get("node_type", "")
        label = resolve_name(n) if t in ("ip_address", "host") else n
        color = "#cccccc"
        size = DEFAULT_NODE_SIZE
        font_size = DEFAULT_FONT_SIZE

        if t in ("ip_address", "host"):
            r = float(d.get("risk", 0.0))
            color = risk_color(r)
            size = HOST_BASE_SIZE + int(r * 20)
        
        
        elif t == "vulnerability":
            cvss = float(d.get("cvss_score", 0.0))
            color = risk_color(cvss / 10.0)
            size = VULN_BASE_SIZE + int(cvss * 1.5)
            # Extract CVE ID and build NVD URL
            cve_id = n  # Node ID is the CVE string
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

          # Rich tooltip with CVSS, description
            desc = d.get("description", "No description available.") or "No description"
            tooltip_lines = [
                f"{cve_id},",
                f"CVSS Score: {cvss:.1f}",
                f"Severity: {risk_color(cvss / 10.0)}",  # Shows color name indirectly
                "",
                desc[:400] + ("..." if len(desc) > 400 else "")
            ]
            tooltip = "<br>".join(tooltip_lines)

            net.add_node(
                n,
                label=cve_id,
                color=color,
                size=size,
                font={"size": font_size},
                shape="square",
                borderWidth=3 if n in hi_nodes else 1,
                title=tooltip,
                **{"url": cve_url, "target": "_blank"}
            )

        net.add_node(
            n, label=label, color=color, size=size, font={"size": font_size},
            shape="dot" if t != "vulnerability" else "square",
            borderWidth=3 if n in hi_nodes else 1,
            title=str(d)[:300]
        )

    for u, v, d in G.edges(data=True):
        p = float(d.get("attack_prob", 0.0))
        color = risk_color(p)
        width = max(1.0, 1.5 + p * 4)
        font_size = 28
        if (u, v) in hi_edges:
            color = "#ff4444"
            width = 4.5
        net.add_edge(
            u, v, color=color, width=width, arrows="to",
            label=d.get("edge_type", "edge"),
            font={"size": font_size},
            title=f"{d.get('edge_type')} prob={p:.3f}"
        )

    net.save_graph(out)
    print(f" Graph saved to {out}")
 #   try:
 #       webbrowser.open(f"file://{os.path.abspath(out)}", new=2)
 #   except Exception:
 #       pass

# -------------------------------------------------------------------
# GEMINI 
# -------------------------------------------------------------------
def list_models_for_key(api_key):
    url = "https://generativelanguage.googleapis.com/v1beta/models"
    headers = {}
    params = {}
    if not api_key:
        print(" No api_key provided to list_models_for_key")
        return None
    if isinstance(api_key, str) and api_key.startswith("ya29"):
        headers["Authorization"] = f"Bearer {api_key}"
    else:
        params["key"] = api_key
        headers["x-goog-api-key"] = api_key
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        if r.status_code != 200:
            print(f" list_models failed: status={r.status_code} text={r.text}")
            return None
        js = r.json()
        return [m.get("name") for m in js.get("models", []) if isinstance(m, dict)]
    except Exception as e:
        print(" list_models failed:", e)
        return None

def pick_model_for_generate(api_key):
    preferred = ["gemini-1.5-flash"]
    models = list_models_for_key(api_key)
    if not models:
        return "models/gemini-1.5-flash"
    simple = [m.split("/")[-1] for m in models]
    for p in preferred:
        if p in simple:
            return next(m for m in models if m.endswith(p))
    return models[0]

def gemini_generate_content(api_key, model_id, prompt):
    base = "https://generativelanguage.googleapis.com/v1beta"
    if model_id and not model_id.startswith("models/"):
        model_id = f"models/{model_id}"
    url = f"{base}/{model_id}:generateContent"
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2000}
    }
    headers = {"Content-Type": "application/json"}
    params = {}
    if not api_key:
        raise RuntimeError("No API key provided for Gemini request")
    if api_key.startswith("ya29"):
        headers["Authorization"] = f"Bearer {api_key}"
    else:
        params["key"] = api_key
        headers["x-goog-api-key"] = api_key
    r = requests.post(url, headers=headers, params=params, json=body, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Gemini API error {r.status_code}: {r.text}\nRequest URL: {r.request.url}")
    js = r.json()
    def collect_string_leaves(o, out=None, limit=3000):
        if out is None:
            out = []
        if len(out) >= limit:
            return out
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for k, v in o.items():
                collect_string_leaves(v, out, limit)
                if len(out) >= limit:
                    break
        elif isinstance(o, list):
            for el in o:
                collect_string_leaves(el, out, limit)
                if len(out) >= limit:
                    break
        return out
    candidates = js.get("candidates") if isinstance(js, dict) else None
    text_out = None
    if candidates and isinstance(candidates, list) and len(candidates) > 0:
        for c in candidates:
            content = c.get("content") if isinstance(c, dict) else None
            if isinstance(content, dict):
                if "text" in content and isinstance(content["text"], str):
                    text_out = content["text"]
                    break
                parts = content.get("parts") or content.get("items") or content.get("outputs")
                if isinstance(parts, list):
                    pieces = []
                    for p in parts:
                        if isinstance(p, dict) and "text" in p and isinstance(p["text"], str):
                            pieces.append(p["text"])
                        elif isinstance(p, str):
                            pieces.append(p)
                    if pieces:
                        text_out = "\n".join(pieces)
                        break
        if text_out is None:
            leaves = collect_string_leaves(candidates[0], out=[], limit=1000)
            if leaves:
                text_out = "\n".join(leaves[:50])
    if not text_out:
        leaves = collect_string_leaves(js, out=[], limit=1000)
        if leaves:
            text_out = "\n".join(leaves[:50])
    truncated_note = ""
    try:
        if isinstance(candidates, list) and len(candidates) > 0:
            fr = candidates[0].get("finishReason")
            if fr and str(fr).upper().startswith("MAX_TOKENS"):
                truncated_note = "\n\n( Output truncated: model finished due to MAX_TOKENS)"
    except Exception:
        pass
    if text_out:
        return (text_out + truncated_note)[:20000]
    try:
        summary = {
            "modelVersion": js.get("modelVersion"),
            "responseId": js.get("responseId"),
            "candidates": [ {"finishReason": c.get("finishReason") if isinstance(c, dict) else None} for c in (js.get("candidates") or []) ],
            "usageMetadata": js.get("usageMetadata")
        }
        return json.dumps(summary, indent=2)
    except Exception:
        return json.dumps(js)[:20000]

def generate_with_gemini_api(prompt: str, api_key: str, model: str = "gemini-1.5-pro"):
    """Use official Gemini SDK with JSON mode enforced."""
    try:
        genai.configure(api_key=api_key)
        gen_model = genai.GenerativeModel(
            model,
            generation_config={
                "response_mime_type": "application/json",  # ← FORCES JSON
                "temperature": 0.2,
                "max_output_tokens": 2048,
            }
        )
        response = gen_model.generate_content(prompt)
        return response.text.strip(), model
    except Exception as e:
        raise RuntimeError(f"Gemini API error: {e}")
    
def generate_with_gemini_sdk(prompt: str, api_key: str, model: str = "models/gemini-pro"):
    """Official SDK with forced JSON."""
    try:
        genai.configure(api_key=api_key)
        
        # Ensure full model name if needed
        if not model.startswith("models/"):
            model = f"models/{model}"
        
        gen_model = genai.GenerativeModel(
            model,
            generation_config={
                "response_mime_type": "application/json",
                "temperature": 0.2,
                "max_output_tokens": 2048,
            }
        )
        response = gen_model.generate_content(prompt)
        raw = response.text.strip()

        # Strip wrappers
        if raw.startswith("```json"):
            raw = raw[7:-3].strip()
        elif raw.startswith("```"):
            raw = raw[3:-3].strip()
        
        return raw, model
    except Exception as e:
        raise RuntimeError(f"Gemini SDK error: {e}")

def get_available_models(api_key: str):
    """Query Gemini API for models YOU can access."""
    try:
        genai.configure(api_key=api_key)
        models = genai.list_models()
        supported = []
        for model in models:
            name = model.name
            # Filter for generation-capable models
            if "generateContent" in model.supported_generation_methods:
                supported.append(name)
                print(f"Available: {name}")
        return supported
    except Exception as e:
     #   print(f"Model discovery failed: {e}")
        return []  # Fallback to known stable models

def explain_paths_with_gemini(paths, G):
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or GEMINI_API_KEY
    if not api_key or api_key == "":
        return " No valid API key found. Please export GEMINI_API_KEY or GOOGLE_API_KEY."
   # print("Discovering available Gemini models...")
    available = get_available_models(api_key)
    if not available:
    #    print("No models found – using fallback.")
        candidates = ["models/gemini-pro"]  # Old stable model
    else:
        # Prefer flash/pro variants, fallback to anything
        candidates = [m for m in available if "flash" in m or "pro" in m]
        if not candidates:
            candidates = available[:2]  # Top 2 available

    print(f"Using models: {candidates}")

    items = []
    for i, (p, s) in enumerate(paths, start=1):
        steps = []
        for j, node_id in enumerate(p):
            nd = G.nodes[node_id]
            if nd.get("node_type") in ("ip_address", "host"):
                # Find services on this host
                services = nd.get("services", [])
                svc_str = ""
                if services:
                    svc = services[0] if isinstance(services[0], dict) else {"service": services[0]}
                    port = svc.get("port", "")
                    service = svc.get("service", "")
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    svc_str = f"{service} {product} {version}".strip()
                    if port:
                        svc_str = f"{svc_str} (port {port})"
                steps.append(f"{node_id} ({svc_str})".strip())
            else:
                # CVE node
                cve_id = node_id
                cvss = nd.get("cvss_score", 0)
                desc = nd.get("description", "")[:60]
                steps.append(f"{cve_id} (CVSS {cvss:.1f})")
        items.append(f"{i}. {' - '.join(steps)} | risk_score={s:.3f}")

    prompt = (f"""You are a red-team penetration tester. You have discovered a real internal network with live hosts and known vulnerabilities.

Your task: For each attack path below, describe **a realistic exploit chain from the attacker’s laptop to a high-value target (the \"safe with gold\")**.

Use **only the IPs, ports, services, and CVEs that appear in the path**. Do **not** invent new vulnerabilities.

Return **only valid JSON**  no markdown, no extra text.

Required JSON fields per path:
- path_index (int)
- path (string): "IP1 (service) - IP2 (CVE-XXXX) - IP3 (privilege escalation) - ..."
- short_explanation (1-2 sentences): Why this path works and what the attacker gains.
- attack_vectors (array of strings): Specific attack types applicable to the CVEs/services in this path (e.g., "remote code execution via SMB", "auth bypass", "information disclosure").
- top_remediations (array of 3 strings): Actionable fixes mapped to the vulnerabilities/services in this path.
- priority_reason (1 sentence): Why fix this first.
- confidence ("high"|"medium"|"low")

Example:
[
    {{
        "path_index": 1,
        "path": "10.128.140.70 (laptop) - 10.128.140.46 (SMB, CVE-2017-0144) - 10.128.140.100 (Domain Controller)",
        "short_explanation": "EternalBlue on SMB allows remote code execution, giving attacker SYSTEM on DC.",
        "attack_vectors": ["remote code execution via SMB"],
        "top_remediations": ["Apply MS17-010", "Disable SMBv1", "Block port 445"],
        "priority_reason": "Direct path to domain admin credentials.",
        "confidence": "high"
    }}
]

Now analyze these **real** paths from the network scan:
""" + "\n".join(items))

    for model in candidates:
        try:
        #    print(f"Trying {model} with forced JSON...")
            text, used = generate_with_gemini_sdk(prompt, api_key, model)
            # Validate JSON
            parsed = json.loads(text)
            if isinstance(parsed, list) and len(parsed) > 0:
                print(f"Success with {used} – Valid JSON array of {len(parsed)} paths")
                return json.dumps(parsed, indent=2)
            else:
                raise ValueError("Not a valid list")
        except Exception as e:
            print(f"{model} failed: {e}")
            continue

    # ---------- DEBUG SAVE ----------
    debug_path = Path(__file__).parent / "data" / "gnn" / "gemini_debug.txt"
    debug_path.parent.mkdir(parents=True, exist_ok=True)
    with open(debug_path, "w", encoding="utf-8") as f:
        f.write(f"PROMPT:\n{prompt}\n\nAVAILABLE MODELS: {available}\nFAILED CANDIDATES: {candidates}")
    print("All models failed – check debug file.")
    return None
#   for model in ["gemini-1.5-flash"]:
#        try:
#            print(f"Trying {model} with forced JSON...")
#            text, used = generate_with_gemini_sdk(prompt, api_key, model)
#            # Validate
#            parsed = json.loads(text)
#            if isinstance(parsed, list) and len(parsed) > 0:
#                print(f"Success with {used} – Valid JSON array of {len(parsed)} paths")
#                return json.dumps(parsed, indent=2)  # Pretty-print for save
#            else:
#                raise ValueError("Not a valid list of paths")
#        except Exception as e:
#            print(f"{model} failed: {e}")
#            continue
    
    # All failed – save debug
#    debug_path = Path("data/gnn/gemini_debug.txt")
#    debug_path.parent.mkdir(parents=True, exist_ok=True)
#    with open(debug_path, "w", encoding="utf-8") as f:
#        f.write(f"Prompt:\n{prompt}\n\nFailed models: {candidates}")
#    return None
#
#    try:
#        parsed = json.loads(text)
#        return json.dumps(parsed, indent=2)
#    except Exception:
#        return "( Gemini did not return JSON)\n\n" + text

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="bipartite_attack_graph.json")
    ap.add_argument("--model", default="gatv2_best.pt")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--source", default=None, help="Manually specify source host/node ID")
    ap.add_argument("--top-source", type=int, default=1, help="Pick Nth-highest risk host (default=1)")
    ap.add_argument("--use-neo4j", action="store_true", help="Load graph directly from Neo4j instead of JSON")
    ap.add_argument("--neo4j-uri", default=NEO4J_URI)
    ap.add_argument("--neo4j-user", default=NEO4J_USER)
    ap.add_argument("--neo4j-pass", default=NEO4J_PASS)
    args = ap.parse_args()

    if args.use_neo4j:
        print(" Loading graph from Neo4j...")
        G = load_graph_from_neo4j(args.neo4j_uri, args.neo4j_user, args.neo4j_pass)
    else:
        print(f" Loading graph from JSON: {args.json}")
        G = load_graph_from_json(args.json)

    nodes, X, edge_index = build_tensors(G)
    print(f" Loaded {len(G.nodes())} nodes, {len(G.edges())} edges.")

    model = GATv2Model(in_channels=X.shape[1])
    if os.path.exists(args.model):
        model.load_state_dict(torch.load(args.model, map_location="cpu"), strict=False)
        print(f" Loaded model {args.model}")
    model.eval()

    with torch.no_grad():
        preds = model(X, edge_index).numpy()
    for i, n in enumerate(nodes):
        if G.nodes[n].get("node_type") in ("ip_address","host"):
            G.nodes[n]["risk"] = float(preds[i])

    assign_conditional_probs(G)

    hosts = [n for n, d in G.nodes(data=True) if d.get("node_type") in ("ip_address","host")]
    if not hosts:
        return print(" No hosts found in graph.")

    if args.source and args.source in hosts:
        src = args.source
    else:
        ranked = sorted(hosts, key=lambda h: G.nodes[h].get("risk",0), reverse=True)
        idx = max(0, min(args.top_source-1, len(ranked)-1))
        src = ranked[idx]

    print(f" Source host: {src} ")

    top_paths = rank_paths(G, src, top=args.top)
    print("\n Top Attack Paths:")
    for p, s in top_paths:
        print(" ".join(p))

    visualize(G, top_paths)

    gemini_json = explain_paths_with_gemini(top_paths, G)

    output_dir = Path(__file__).parent / "data" / "gnn"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if gemini_json is None:
        print("Gemini explanations skipped (no API key or all models failed).")
    else:
        json_path = output_dir / "gemini_output.json"
        txt_path = output_dir / "gemini_output.txt"
        try:
            parsed = json.loads(gemini_json)
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2, ensure_ascii=False)
            print(f"Gemini output saved to {json_path}")
        except json.JSONDecodeError as e:
            print(f"Final validation failed (shouldn't happen): {e}")
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(gemini_json)
            print(f"Raw saved to {txt_path}")
        except Exception as e:
            print(f"Save error: {e}")
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(str(gemini_json))

if __name__ == "__main__":
    main()
