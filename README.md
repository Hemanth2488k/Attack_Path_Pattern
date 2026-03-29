# 🚀 Context-Aware Attack Path Planner

A cybersecurity intelligence platform that scans networks, builds attack graphs, predicts risk using Graph Neural Networks (GATv2), and generates AI-powered explanations using Gemini.

---

## 📌 Overview

This project provides an end-to-end pipeline for:

* Network discovery & scanning (Nmap)
* Graph-based risk prediction (GATv2)
* Attack graph visualization (PyVis)
* AI-driven explanations (Gemini)
* Interactive dashboard (Streamlit)

---

## 🏗️ Architecture

```
[ Network Scan ]
       ↓
[ Graph Builder ]
       ↓
[ GATv2 Risk Model ]
       ↓
[ Attack Path Ranking ]
       ↓
[ Gemini AI Explanations ]
       ↓
[ Streamlit Dashboard ]
```

---

## ⚙️ Features

### 🔎 Automated Network Scanning

* Detects active hosts
* Scans ports and services
* Fetches CVEs from NVD

### 🧠 Graph Neural Network (GATv2)

* Predicts risk scores
* Uses vulnerability and service features

### 🕸️ Attack Graph Generation

* Hosts ↔ Vulnerabilities mapping
* Lateral movement edges

### 🤖 Gemini AI Explanations

* Real-world attack chains
* Attack vectors and remediations

### 📊 Streamlit Dashboard

* Pipeline monitoring
* Graph visualization
* AI explanations

---

## 📂 Project Structure

```
├── app.py
├── new.py
├── gat_gemini.py
├── requirements.txt
├── data/
│   └── gnn/
```

---

## 🧪 Installation

### 1. Clone Repository

```
git clone <your-repo-url>
cd attack-path-planner
```

### 2. Create Virtual Environment

```
python -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```
pip install -r requirements.txt
```

---

## 🔑 Environment Setup

```
export GEMINI_API_KEY=your_api_key
```

---

## ▶️ Usage

### Run Full App

```
streamlit run app.py
```

### Manual Execution

```
python new.py
python gat_gemini.py --json data/gnn/bipartite_attack_graph.json
```

---

## 📊 Outputs

* bipartite_attack_graph.json
* hosts_vulnerabilities.json
* gemini_output.json
* attack_graph.html

---

## 🧠 Workflow

1. Scan network
2. Detect services & vulnerabilities
3. Build attack graph
4. Predict risk using GATv2
5. Rank attack paths
6. Generate AI explanations

---

## 🛠️ Tech Stack

* Python
* Streamlit
* PyTorch
* NetworkX
* PyVis
* Neo4j
* Gemini API

---

## ⚠️ Requirements

* Nmap installed
* Internet for CVE fetching
* Gemini API key

---

## 🚧 Future Scope

* Real-time monitoring
* SIEM integration
* Advanced threat modeling

---

## 👨‍💻 Author

Hemanth Koutharapu

---

## 📜 License

See LICENSE file.
