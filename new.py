#!/usr/bin/env python3
import subprocess, socket, ipaddress, requests, json, time, concurrent.futures, random, os
from tqdm import tqdm

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from neo4j import GraphDatabase
from pathlib import Path

# -----------------------------------
# CONFIG
# -----------------------------------
SCAN_TIMEOUT = 30
THREADS = 20  # Increased for faster scanning
HOST_DISCOVERY_TIMEOUT = 90
PORT_SCAN_TIMEOUT = 45
SERVICE_SCAN_TIMEOUT = 30
TOP_PORTS = [22, 80, 443, 445, 3306, 3389, 21, 25, 53, 110, 135, 139, 143, 3389, 5432, 5900, 8080, 8443]
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 0.6  # Seconds between requests to avoid rate limiting

# Neo4j config from env (if present)
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "password")

# -----------------------------------
# OUTPUT CONFIG
# -----------------------------------
OUTPUT_DIR = Path(__file__).parent / "data" / "gnn"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)  # Create if not exists
# -----------------------------------
# NETWORK DISCOVERY
# -----------------------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def get_subnet(ip):
    return str(ipaddress.ip_network(ip + "/24", strict=False))

def fast_host_scan(subnet):
    """Use nmap -sn with aggressive timing to find live hosts quickly."""
    # Use -T4 for aggressive timing, -n to skip DNS resolution, --min-rate for speed
    cmd = ["nmap", "-sn", "-T4", "-n", "--min-rate", "5000", subnet]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=HOST_DISCOVERY_TIMEOUT)
        hosts = []
        for line in res.stdout.splitlines():
            if "Nmap scan report for" in line:
                # Handle both IP-only and hostname cases
                parts = line.split()
                if len(parts) >= 5 and parts[-1].startswith("("):
                    ip = parts[-1].strip("()")
                else:
                    ip = parts[-1]
                # Validate it's an IP address
                try:
                    ipaddress.ip_address(ip)
                    hosts.append(ip)
                except ValueError:
                    continue
        print(f" Found {len(hosts)} active hosts")
        return hosts
    except Exception as e:
        print(f"[!] Discovery failed: {e}")
        return []

def scan_host_ports(host):
    """Scan ports quickly for one host with improved accuracy."""
    try:
        cmd = ["nmap", "-sV", "-O", "--osscan-limit", host]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=PORT_SCAN_TIMEOUT)
        ports = []
        for line in r.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                try:
                    port_str = line.split()[0].split("/")[0]
                    port = int(port_str)
                    ports.append(port)
                except (ValueError, IndexError):
                    continue
        if ports:
            print(f"  {host}: {len(ports)} open ports")
        return host, ports
    except subprocess.TimeoutExpired:
        print(f"  [!] {host}: Scan timeout")
        return host, []
    except Exception as e:
        print(f"  [!] {host}: Scan error - {e}")
        return host, []

# -----------------------------------
# SERVICE + VULNERABILITY ENRICHMENT
# -----------------------------------
def detect_services(host, ports):
    """Enhanced service detection for specific ports."""
    if not ports:
        return []
    
    ports_to_scan = ports[:50] if len(ports) > 50 else ports
    port_range = ",".join(map(str, ports_to_scan))
    
    cmd = ["nmap", "-sV", "-T4", "-n", "--version-intensity", "5", "-p", port_range, host]
    services = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=SERVICE_SCAN_TIMEOUT)
        for line in r.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split(None, 6)
                if len(parts) >= 3:
                    try:
                        port = int(parts[0].split("/")[0])
                        state = parts[1]
                        svc = parts[2]
                        product = ""
                        version = ""
                        if len(parts) >= 4:
                            version_info = " ".join(parts[3:])
                            if version_info:
                                tokens = version_info.split()
                                if tokens:
                                    product = tokens[0]
                                    for token in tokens[1:]:
                                        if any(c.isdigit() for c in token):
                                            version = token
                                            break
                        services.append({
                            "port": port,
                            "service": svc,
                            "product": product,
                            "version": version,
                            "raw_banner": " ".join(parts[3:]) if len(parts) > 3 else ""
                        })
                    except (ValueError, IndexError):
                        continue
        return services
    except subprocess.TimeoutExpired:
        print(f"    [!] Service scan timeout for {host}")
        return []
    except Exception as e:
        print(f"    [!] Service scan error for {host}: {e}")
        return []

def query_nvd(product, version):
    """Query NVD for CVEs with rate limiting and better error handling."""
    if not product or product == "unknown":
        return []
    product_clean = product.lower().strip()
    version_clean = version.strip() if version else ""
    search_query = f"{product_clean} {version_clean}".strip()
    params = {"keywordSearch": search_query, "resultsPerPage": 10}
    try:
        time.sleep(NVD_RATE_LIMIT)
        r = requests.get(NVD_API, params=params, timeout=15)
        vulns = []
        if r.status_code == 200:
            data = r.json()
            for v in data.get("vulnerabilities", []):
                try:
                    cve_data = v.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    descriptions = cve_data.get("descriptions", [])
                    desc = descriptions[0].get("value", "") if descriptions else "No description available"
                    metrics = cve_data.get("metrics", {})
                    cvss = 0.0
                    severity = "UNKNOWN"
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                        cvss = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss = cvss_data.get("baseScore", 0.0)
                    published = cve_data.get("published", "")
                    vulns.append({
                        "id": cve_id,
                        "cvss": float(cvss),
                        "severity": severity,
                        "desc": desc[:200],
                        "published": published
                    })
                except (KeyError, IndexError, TypeError) as e:
                    continue
            if vulns:
                print(f"      [+] Found {len(vulns)} CVEs for {product_clean}")
        elif r.status_code == 403:
            print(f"      [!] NVD API rate limited - consider adding API key")
        else:
            print(f"      [!] NVD API returned status {r.status_code}")
        return vulns
    except requests.Timeout:
        print(f"      [!] NVD query timeout for {product_clean}")
        return []
    except Exception as e:
        print(f"      [!] NVD query error for {product_clean}: {e}")
        return []

# -----------------------------------
# GRAPH CONSTRUCTION
# -----------------------------------
def build_graph(hosts_ports):
    print(f"\n[+] Building attack graph for {len(hosts_ports)} hosts...")
    graph = {"nodes": {}, "edges": [], "hosts_detailed": {}}

    # Phase 1: Create host nodes with complete information
    for host, ports in hosts_ports.items():
        graph["nodes"][host] = {
            "node_type": "ip_address",
            "open_ports": ports,
            "open_ports_count": len(ports),
            "vuln_count": 0,
            "cvss_mean": 0.0,
            "cvss_max": 0.0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "services": [],
            "cves": []
        }
        graph["hosts_detailed"][host] = {
            "ip_address": host,
            "open_ports": ports,
            "services": [],
            "vulnerabilities": []
        }

    # Phase 2: Vulnerability enrichment
    print("\n[+] Scanning services and gathering CVEs...")
    for host, ports in tqdm(hosts_ports.items(), desc="Service detection"):
        print(f"\n   Processing {host}")
        services = detect_services(host, ports)
        all_cvss = []
        vulns_total = 0
        host_cves = []
        for s in services:
            print(f"    Port {s['port']}: {s['service']} ({s['product']} {s['version']})")
            graph["nodes"][host]["services"].append(s)
            graph["hosts_detailed"][host]["services"].append(s)
            vulns = query_nvd(s["product"], s["version"])
            for v in vulns:
                cve_id = v["id"]
                cvss = v["cvss"]
                severity = v.get("severity", "UNKNOWN")
                desc = v["desc"]
                published = v.get("published", "")
                vulns_total += 1
                all_cvss.append(cvss)
                cve_entry = {
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "severity": severity,
                    "description": desc,
                    "published": published,
                    "affected_service": s["service"],
                    "affected_port": s["port"],
                    "product": s["product"],
                    "version": s["version"]
                }
                host_cves.append(cve_entry)
                graph["hosts_detailed"][host]["vulnerabilities"].append(cve_entry)
                if cve_id not in graph["nodes"]:
                    graph["nodes"][cve_id] = {
                        "node_type": "vulnerability",
                        "cvss_score": cvss,
                        "severity": severity,
                        "description": desc,
                        "published": published
                    }
                graph["edges"].append({
                    "src": host,
                    "dst": cve_id,
                    "edge_type": "has_vulnerability",
                    "edge_weight": cvss / 10.0,
                    "port": s["port"],
                    "service": s["service"]
                })
        graph["nodes"][host]["cves"] = host_cves
        if all_cvss:
            graph["nodes"][host]["vuln_count"] = vulns_total
            graph["nodes"][host]["cvss_max"] = max(all_cvss)
            graph["nodes"][host]["cvss_mean"] = round(sum(all_cvss) / len(all_cvss), 2)
            graph["nodes"][host]["high_vulns"] = sum(1 for x in all_cvss if x >= 7.0)
            graph["nodes"][host]["medium_vulns"] = sum(1 for x in all_cvss if 4.0 <= x < 7.0)
            graph["hosts_detailed"][host]["total_vulnerabilities"] = vulns_total
            graph["hosts_detailed"][host]["max_cvss"] = max(all_cvss)
            graph["hosts_detailed"][host]["avg_cvss"] = round(sum(all_cvss) / len(all_cvss), 2)

    # Phase 3: Add IP↔IP edges (lateral movement possibility)
    hosts = list(hosts_ports.keys())
    for i in range(len(hosts)):
        for j in range(i + 1, len(hosts)):
            graph["edges"].append({
                "src": hosts[i],
                "dst": hosts[j],
                "edge_type": "network_connectivity",
                "edge_weight": 1.0
            })

    # Summary statistics
    total_services = sum(len(graph["nodes"][h].get("services", [])) for h in hosts_ports.keys())
    total_vulns = sum(len(graph["nodes"][h].get("cves", [])) for h in hosts_ports.keys())
    print(f"\n Graph built successfully:")
    print(f"   Nodes: {len(graph['nodes'])} ({len(hosts_ports)} hosts, {len(graph['nodes']) - len(hosts_ports)} CVEs)")
    print(f"   Edges: {len(graph['edges'])}")
    print(f"   Services: {total_services}")
    print(f"   Vulnerabilities: {total_vulns}")
    return graph

# -----------------------------------
# FEATURE CONSTRUCTION (6D)
# -----------------------------------
def attach_features(graph):
    """Attach 6D numeric features for GATv2: [ports, vuln_count, mean_cvss, max_cvss, high_vulns, medium_vulns]."""
    for n, d in graph["nodes"].items():
        if d.get("node_type") == "ip_address":
            d["features"] = [
                d.get("open_ports_count", 0),
                d.get("vuln_count", 0),
                d.get("cvss_mean", 0.0) / 10.0,
                d.get("cvss_max", 0.0) / 10.0,
                d.get("high_vulns", 0),
                d.get("medium_vulns", 0)
            ]
        else:
            d["features"] = [d.get("cvss_score", 0.0) / 10.0, 0, 0, 0, 0, 0]
    return graph

# -----------------------------------
# NEO4J PUSH
# -----------------------------------
def push_to_neo4j(graph, uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS):
    """Push graph nodes/edges into Neo4j using MERGE to avoid duplication."""
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        # Push vulnerability nodes first
        for nid, meta in graph["nodes"].items():
            if meta.get("node_type") == "vulnerability":
                cvss = float(meta.get("cvss_score", meta.get("cvss", 0.0)))
                desc = meta.get("description", "")
                session.run("""
                MERGE (v:Vulnerability {cve:$cve})
                SET v.cvss = $cvss, v.description = $desc
                """, cve=nid, cvss=cvss, desc=desc)

        # Push host nodes with numeric properties
        for nid, meta in graph["nodes"].items():
            if meta.get("node_type") == "ip_address":
                ports = meta.get("open_ports", [])
                ports_count = int(meta.get("open_ports_count", len(ports)))
                vuln_count = int(meta.get("vuln_count", 0))
                cvss_mean = float(meta.get("cvss_mean", 0.0))
                cvss_max = float(meta.get("cvss_max", 0.0))
                high_vulns = int(meta.get("high_vulns", 0))
                medium_vulns = int(meta.get("medium_vulns", 0))
                services = meta.get("services", [])
                session.run("""
                MERGE (h:Host {ip:$ip})
                SET h.open_ports = $ports,
                    h.ports_count = $ports_count,
                    h.vuln_count = $vuln_count,
                    h.cvss_mean = $cvss_mean,
                    h.cvss_max = $cvss_max,
                    h.high_vulns = $high_vulns,
                    h.medium_vulns = $medium_vulns,
                    h.services = $services,
                    h.last_seen = $now,
                    h.status = "active"
                """, ip=nid, ports=ports, ports_count=ports_count, vuln_count=vuln_count,
                     cvss_mean=cvss_mean, cvss_max=cvss_max, high_vulns=high_vulns,
                     medium_vulns=medium_vulns, services=services, now=time.strftime("%Y-%m-%dT%H:%M:%SZ"))

        # Push edges
        for e in graph["edges"]:
            src, dst = e.get("src"), e.get("dst")
            etype = e.get("edge_type", "edge")
            if etype == "has_vulnerability":
                # host -> vulnerability
                session.run("""
                MATCH (h:Host {ip:$src})
                MERGE (v:Vulnerability {cve:$dst})
                MERGE (h)-[r:HAS_VULN]->(v)
                SET r.edge_weight = $edge_weight,
                    r.port = $port,
                    r.service = $service,
                    r.last_seen = $now
                """, src=src, dst=dst, edge_weight=float(e.get("edge_weight", 0.0)),
                     port=e.get("port", None), service=e.get("service", None), now=time.strftime("%Y-%m-%dT%H:%M:%SZ"))
            elif etype == "network_connectivity":
                session.run("""
                MERGE (a:Host {ip:$src})
                MERGE (b:Host {ip:$dst})
                MERGE (a)-[r:NETWORK_CONNECTIVITY]->(b)
                SET r.edge_weight = $edge_weight, r.last_seen = $now
                """, src=src, dst=dst, edge_weight=float(e.get("edge_weight", 1.0)), now=time.strftime("%Y-%m-%dT%H:%M:%SZ"))
    driver.close()
    print(" Pushed graph to Neo4j.")

# -----------------------------------
# SAVE OUTPUT
# -----------------------------------
def save_outputs(graph):
    # Save JSON graph
    graph_path = OUTPUT_DIR / "bipartite_attack_graph.json"
    with open(graph_path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)
    print(f"Saved bipartite_attack_graph.json - {graph_path}")

    # Save host report
    hosts_report = {
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_hosts": len(graph["hosts_detailed"]),
        "hosts": graph["hosts_detailed"]
    }
    hosts_path = OUTPUT_DIR / "hosts_vulnerabilities.json"
    with open(hosts_path, "w", encoding="utf-8") as f:
        json.dump(hosts_report, f, indent=2)
    print(f"Saved hosts_vulnerabilities.json - {hosts_path}")

    # Save PyTorch tensor (if available)
    if HAS_TORCH:
        nodes = list(graph["nodes"].keys())
        feats = [graph["nodes"][n]["features"] for n in nodes]
        src, dst = [], []
        for e in graph["edges"]:
            if e["src"] in nodes and e["dst"] in nodes:
                src.append(nodes.index(e["src"]))
                dst.append(nodes.index(e["dst"]))
        payload = {
            "node_ids": nodes,
            "node_features": torch.tensor(feats, dtype=torch.float),
            "edge_index": torch.tensor([src, dst], dtype=torch.long),
        }
        pt_path = OUTPUT_DIR / "bipartite_attack_graph.pt"
        torch.save(payload, pt_path)
        print(f"Saved bipartite_attack_graph.pt - {pt_path}")

# -----------------------------------
# MAIN
# -----------------------------------
def main():
    print(" FAST ATTACK GRAPH GENERATOR STARTING...")
    local_ip = get_local_ip()
    subnet = get_subnet(local_ip)
    print(f"Local IP: {local_ip} | Subnet: {subnet}")

    print("[1] Scanning for active hosts...")
    hosts = fast_host_scan(subnet)
    if not hosts:
        print("No active hosts found.")
        return

    print(f"[2] Scanning open ports on {len(hosts)} hosts...")
    hosts_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = [ex.submit(scan_host_ports, h) for h in hosts]
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
            h, ports = fut.result()
            if ports:
                hosts_ports[h] = ports

    if not hosts_ports:
        print(" No open ports found on any host.")
        return

    print("[3] Building and enriching graph...")
    graph = build_graph(hosts_ports)
    graph = attach_features(graph)
    save_outputs(graph)

    # Push to Neo4j baseline (MERGE-safe)
    try:
        push_to_neo4j(graph)
    except Exception as e:
        print(f"[!] Failed to push to Neo4j: {e}")

    print("\n Complete. Graph ready for GATv2 + PyVis + Neo4j.")

if __name__ == "__main__":
    main()
