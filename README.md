# 🔬 The Obsidian Lens

> **Advanced Behavioral Network Forensics & Active Intrusion Prevention Platform**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-14-000000?style=flat&logo=nextdotjs)](https://nextjs.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-F7931E?style=flat&logo=scikitlearn)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-Research-purple)](./LICENSE)

---

## Overview

The Obsidian Lens is an enterprise-grade network security platform that **fingerprints attackers by behavior, not by IP**. It passively captures and analyzes network traffic (`.pcap` files or live NIC streams), extracts 49 behavioral dimensions from each TCP/IP flow, and classifies them using a trained Random Forest ensemble. Identified threats are linked to persistent identities and can be mitigated in real-time via OS-level firewall integration.

---

## Table of Contents

1. [Key Features](#key-features)
2. [System Architecture](#system-architecture)
3. [ML Pipeline — Deep Dive](#ml-pipeline--deep-dive)
4. [Feature Set (49 Behavioral Dimensions)](#feature-set-49-behavioral-dimensions)
5. [Datasets](#datasets)
6. [Threat Detection Classes](#threat-detection-classes)
7. [Identity Engine](#identity-engine)
8. [Active IPS (Windows Firewall)](#active-ips-windows-firewall)
9. [PDF Forensic Reports](#pdf-forensic-reports)
10. [Installation](#installation)
11. [Usage](#usage)
12. [Project Structure](#project-structure)

---

## Key Features

| Feature | Description |
|---|---|
| **Behavioral Fingerprinting** | Tracks attackers by 49 behavioral dimensions — defeats VPN/proxy masking |
| **Multi-class Threat Detection** | Classifies 14+ specific threat types from DDoS to SQL Injection |
| **Explainable AI (XAI)** | Plain-English explanations of every AI decision |
| **Identity Tracking** | Cross-session User→MAC→IP relationship graph |
| **Active IPS** | Real-time `netsh` Windows Firewall rule injection on Block |
| **Reinforcement Learning** | Analyst feedback loop with sliding-window online retraining |
| **PDF Forensic Reports** | Professional court-admissible multi-page report generation |
| **Live Capture** | Promiscuous NIC sniffing via Scapy/Npcap |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Next.js 14)                    │
│  Dashboard │ RecordsTable │ IdentityPanel │ UploadZone          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API (Flask)
┌──────────────────────────▼──────────────────────────────────────┐
│                       BACKEND (Python Flask)                    │
│                                                                 │
│  ┌─────────────┐   ┌──────────────────┐   ┌─────────────────┐  │
│  │ pcap_parser │ → │ feature_extractor│ → │   classifier    │  │
│  │  (Scapy)    │   │  (49 features)   │   │ (RandomForest)  │  │
│  └─────────────┘   └──────────────────┘   └────────┬────────┘  │
│                                                     │           │
│  ┌──────────────────────────┐   ┌───────────────────▼────────┐  │
│  │   identity_db (SQLite)   │ ← │   upsert_identity +        │  │
│  │   User→MAC→IP graph      │   │   cosine similarity match  │  │
│  └──────────┬───────────────┘   └────────────────────────────┘  │
│             │                                                    │
│  ┌──────────▼───────────────┐   ┌────────────────────────────┐  │
│  │  block_identity (netsh)  │   │  pdf_report (ReportLab)    │  │
│  │  Windows Firewall IPS    │   │  Professional PDF export   │  │
│  └──────────────────────────┘   └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ML Pipeline — Deep Dive

### 1. Data Ingestion
Raw `.pcap` files are parsed by `core/pcap_parser.py` using **Scapy**. Packets are grouped into **bidirectional flows** using a canonical 5-tuple key:
```
(min(srcIP,dstIP), max(srcIP,dstIP), srcPort, dstPort, protocol)
```
The canonical ordering ensures forward and backward packets of the same connection are grouped under one flow, regardless of capture direction.

### 2. Feature Extraction (`core/feature_extractor.py`)
For each flow, 49 statistical differentials are computed across forward and backward packet streams.  
**IP addresses are deliberately stripped** before feature computation — only behavioral signals are retained.  
This ensures the model cannot overfit to specific addresses and generalizes across IP-hopping/VPN scenarios.

### 3. Preprocessing (`ml/preprocessor.py`)
- **Missing values:** All `NaN` and `±inf` filled with `0`
- **Scaling:** `sklearn.preprocessing.StandardScaler` — zero mean, unit variance per feature
- **Serialization:** Fitted scaler saved to `models/scaler.pkl` and hot-loaded for inference

### 4. Classification (`ml/classifier.py`)
- **Model:** `sklearn.ensemble.RandomForestClassifier`
- **Estimators:** 100 decision trees (`n_estimators=100`)
- **Class balancing:** `class_weight='balanced'` — automatically compensates for CICIDS2017 class imbalance
- **Parallelism:** `n_jobs=-1` — uses all CPU cores during training
- **Confidence:** `predict_proba()` → `max(probability)` per sample
- **Explainability:** `model.feature_importances_` → top-N Gini importance ranks for XAI

### 5. Identity Matching (Cosine Similarity)
After classification, each flow's 10-dimensional behavioral fingerprint is compared against stored fingerprints using **Cosine Similarity**:
```
similarity = (v1 · v2) / (|v1| × |v2|)
```
If `similarity ≥ 0.85`, the flow is attributed to an existing identity (persistent cross-session tracking). Otherwise, a new codename (e.g. `User004`) is generated.

### 6. Reinforcement Learning (Online Retraining)
The analyst can relabel misclassified flows via the UI. The corrected sample is appended to `data/training_data.csv`. A sliding-window retrain is then triggered:
- **Window size:** Last 5,000 rows retained (older data evicted)
- **Lock:** `threading.Lock` prevents concurrent write corruption
- **Hot-swap:** New model is serialized to `models/` and immediately loaded into inference path without server restart

---

## Feature Set (49 Behavioral Dimensions)

> **Category 1: Temporal (21 features)**

| # | Feature | Description |
|---|---|---|
| 1 | `flow_duration` | Total duration of the flow (seconds) |
| 2 | `iat_mean` | Mean inter-arrival time between all packets |
| 3 | `iat_std` | Standard deviation of inter-arrival times |
| 4 | `iat_min` | Minimum inter-arrival time |
| 5 | `iat_max` | Maximum inter-arrival time |
| 6 | `fwd_iat_mean` | Mean IAT for forward direction packets |
| 7 | `fwd_iat_std` | Std Dev of forward IAT |
| 8 | `fwd_iat_min` | Min forward IAT |
| 9 | `fwd_iat_max` | Max forward IAT |
| 10 | `bwd_iat_mean` | Mean IAT for backward direction packets |
| 11 | `bwd_iat_std` | Std Dev of backward IAT |
| 12 | `bwd_iat_min` | Min backward IAT |
| 13 | `bwd_iat_max` | Max backward IAT |
| 14 | `active_time_mean` | Mean duration of active transmission bursts |
| 15 | `active_time_std` | Std Dev of active periods |
| 16 | `active_time_min` | Shortest active burst observed |
| 17 | `active_time_max` | Longest active burst observed |
| 18 | `idle_time_mean` | Mean idle gap between active periods |
| 19 | `idle_time_std` | Std Dev of idle gaps |
| 20 | `idle_time_min` | Shortest idle gap |
| 21 | `idle_time_max` | Longest idle gap |

> **Category 2: Spatial — Packet Lengths (14 features)**

| # | Feature | Description |
|---|---|---|
| 22 | `total_fwd_packets` | Count of forward direction packets |
| 23 | `total_bwd_packets` | Count of backward direction packets |
| 24 | `total_fwd_bytes` | Total bytes sent in forward direction |
| 25 | `total_bwd_bytes` | Total bytes sent in backward direction |
| 26 | `fwd_pkt_len_mean` | Mean length of forward packets (bytes) |
| 27 | `fwd_pkt_len_std` | Std Dev of forward packet lengths |
| 28 | `fwd_pkt_len_min` | Smallest forward packet |
| 29 | `fwd_pkt_len_max` | Largest forward packet |
| 30 | `bwd_pkt_len_mean` | Mean length of backward packets |
| 31 | `bwd_pkt_len_std` | Std Dev of backward packet lengths |
| 32 | `bwd_pkt_len_min` | Smallest backward packet |
| 33 | `bwd_pkt_len_max` | Largest backward packet |
| 34 | `avg_packet_size` | Mean across all packets in both directions |
| 35 | `pkt_len_variance` | Variance of all packet sizes |

> **Category 3: Volumetric & Directional (4 features)**

| # | Feature | Description |
|---|---|---|
| 36 | `flow_bytes_per_sec` | Total bytes / flow duration |
| 37 | `flow_packets_per_sec` | Total packets / flow duration |
| 38 | `down_up_ratio` | Backward bytes / Forward bytes (asymmetry) |
| 39 | `fwd_bwd_packet_ratio` | Forward packets / Backward packets |

> **Category 4: TCP/IP Flags & Headers (10 features)**

| # | Feature | Description |
|---|---|---|
| 40 | `init_win_fwd` | Initial TCP window size (forward) |
| 41 | `init_win_bwd` | Initial TCP window size (backward) |
| 42 | `fwd_header_len` | Cumulative TCP/IP header bytes (forward) |
| 43 | `bwd_header_len` | Cumulative TCP/IP header bytes (backward) |
| 44 | `fin_flag_count` | Count of packets with FIN flag set |
| 45 | `syn_flag_count` | Count of packets with SYN flag set |
| 46 | `rst_flag_count` | Count of packets with RST flag set |
| 47 | `psh_flag_count` | Count of packets with PSH flag set |
| 48 | `ack_flag_count` | Count of packets with ACK flag set |
| 49 | `urg_flag_count` | Count of packets with URG flag set |

> **Extracted but excluded from ML (display/XAI only):**  
> `tls_*` (11 features), `spl_1..10` (10 features), `burst_*` (4 features), `ttl_*`, `dns_query_count`, `total_packets`

---

## Datasets

### Primary: CICIDS2017 (Canadian Institute for Cybersecurity)
**Source:** University of New Brunswick — [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

| Day | Capture File | Traffic Types |
|---|---|---|
| Monday | `Monday-WorkingHours.pcap` | Benign background traffic only |
| Tuesday | `Tuesday-WorkingHours.pcap` | Benign + FTP-Patator + SSH-Patator |
| Wednesday | `Wednesday-WorkingHours.pcap` | Benign + DoS Slowloris + DoS Slowhttptest + DoS Hulk + DoS GoldenEye + Heartbleed |
| Thursday AM | `Thursday-Morning-WebAttacks.pcap` | Benign + Web Attack (Brute Force, XSS, SQL Injection) |
| Thursday PM | `Thursday-Afternoon-Infiltration.pcap` | Benign + Infiltration attempts |
| Friday AM | `Friday-Morning-PortScan.pcap` | Benign + PortScan |
| Friday PM | `Friday-Afternoon-DDos.pcap` | Benign + DDoS |
| Friday PM | `Friday-Afternoon-Botnet.pcap` | Benign + Bot |

**CICFlowMeter CSV columns → mapped to 49 BENFET features** via `ml/real_dataset_loader.py`.

### Secondary: Synthetic Baseline (Bootstrap)
On first launch with no model, BENFET auto-generates a balanced synthetic dataset via `ml/dataset_generator.py`:
- **Profiles:** `benign`, `ddos`, `brute_force`, `apt`, `ransomware`, `botnet`, `cryptominer`
- **Samples:** 100 per profile by default
- **Purpose:** Cold-start bootstrap only — replaced by real CICIDS2017 data after first RL cycle

### Tertiary (Planned): ISCX VPN-NonVPN
For encrypted/VPN traffic classification. Integration in progress.

---

## Threat Detection Classes

| Threat Class | CICIDS2017 Source Day | Detection Signal |
|---|---|---|
| **Benign** (Safe Traffic) | All days | Low IAT variance, normal window sizes, balanced ratios |
| **DDoS** | Friday PM | Massive `syn_flag_count`, high `flow_packets_per_sec`, near-zero `down_up_ratio` |
| **DoS Hulk** | Wednesday | Extremely high `flow_bytes_per_sec`, large forward packet counts |
| **DoS GoldenEye** | Wednesday | Slow `flow_duration`, low packet rate, sustained `ack_flag_count` |
| **DoS Slowloris** | Wednesday | Very long `flow_duration`, extremely low `flow_packets_per_sec` |
| **DoS Slowhttptest** | Wednesday | Similar to Slowloris — high `idle_time_max`, minimal `bwd_pkt_len_mean` |
| **FTP-Patator** | Tuesday | Repeated SYN/FIN cycles, high `fin_flag_count`, small packet sizes |
| **SSH-Patator** | Tuesday | Same pattern on port 22 flows |
| **PortScan** | Friday AM | Very high `syn_flag_count`, near-zero `flow_duration`, many unique `dst_ip` |
| **Web Attack — Brute Force** | Thursday AM | Repeated short flows, elevated `rst_flag_count` |
| **Web Attack — XSS** | Thursday AM | Moderate flows, high `psh_flag_count`, unusual `fwd_pkt_len_mean` |
| **Web Attack — SQL Injection** | Thursday AM | Short `flow_duration`, high `psh_flag_count`, low `bwd_pkt_len_mean` |
| **Infiltration** | Thursday PM | Low-and-slow flows, long `idle_time_mean`, behaviorally close to benign |
| **Botnet** | Friday PM | Regular `iat_mean`, periodic `burst_count`, consistent `down_up_ratio` |

---

## Identity Engine

**File:** `core/identity_db.py`  
**Database:** SQLite with WAL journal mode for concurrent write safety  
**Schema:**

```
users (id, codename, category, threat_type, confidence, is_blocked, first_seen, last_seen)
  └── mac_addresses (mac_address, first_seen, last_seen)
        └── ip_addresses (ip_address, first_seen, last_seen)
identity_events (event_type, details, timestamp)
```

**Resolution priority (highest → lowest):**
1. JA3 TLS fingerprint hash match
2. MAC address match
3. Behavioral cosine similarity ≥ 0.85 (10-D vector)
4. IP address fallback

**10D behavioral fingerprint vector:**
```python
['flow_duration', 'iat_mean', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
 'flow_bytes_per_sec', 'flow_packets_per_sec', 'fwd_iat_mean',
 'bwd_iat_mean', 'down_up_ratio', 'active_time_mean']
```

---

## Active IPS (Windows Firewall)

When **Block** is triggered on the Dashboard:

```python
# For each IP associated with the identity:
netsh advfirewall firewall add rule name="BENFET_BLOCK_User_X_IP_IN"  dir=in  action=block remoteip=<IP>
netsh advfirewall firewall add rule name="BENFET_BLOCK_User_X_IP_OUT" dir=out action=block remoteip=<IP>

# On Unblock:
netsh advfirewall firewall delete rule name="BENFET_BLOCK_User_X_IP_IN"
netsh advfirewall firewall delete rule name="BENFET_BLOCK_User_X_IP_OUT"
```

> **Requirement:** `python app.py` must be launched from an **Administrator** terminal.

---

## PDF Forensic Reports

Generated via `reports/pdf_report.py` (ReportLab).

**Report Structure:**
1. **Cover Page** — Threat Level badge (CRITICAL/ELEVATED/CLEAR), metadata grid, behavioral fingerprinting summary
2. **Page 2: XAI** — Feature importance bar chart (top 10 Gini scores, fully human-readable), plain-English AI insight conclusions
3. **Page 3: Flow Table** — Top 50 classified flows sorted by maliciousness then confidence, with Src→Dst IPs
4. **Protocol Distribution** — Packet/byte breakdown per protocol
5. **Top Network Flows** — Highest-traffic flows with duration and size
6. **DNS Analysis** — Rendered only when DNS queries > 0

---

## Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- [Npcap](https://npcap.com/) (for live capture on Windows)
- **Administrator terminal** (for Windows Firewall IPS feature)

### Backend
```bash
cd BENFET_fixed
pip install -r requirements.txt
python app.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open: **http://localhost:3000**

---

## Usage

1. **Upload PCAP** — Drag and drop any `.pcap` file into the Upload Zone
2. **Analyze** — Click Analyze to run the full ML pipeline
3. **Review** — Inspect the Flow Classifications table and AI explanations
4. **Block** — Click Block on any identity in the Identity Panel to apply real-time firewall rules
5. **Report** — Export a PDF forensic report (single or batch/cumulative)
6. **Reinforce** — Select misclassified flows and submit corrected labels to retrain the model

---

## Project Structure

```
BENFET_fixed/
├── app.py                      # Flask API — all endpoints
├── config.py                   # Path constants, thresholds
├── core/
│   ├── pcap_parser.py          # Scapy PCAP ingestion → raw flows
│   ├── feature_extractor.py    # 49-feature behavioral vector computation
│   ├── flow_analyzer.py        # Protocol stats, DNS analysis, flow summaries
│   ├── identity_db.py          # SQLite identity graph + netsh IPS
│   └── topology_mapper.py      # Network graph construction
├── ml/
│   ├── classifier.py           # RandomForestClassifier wrapper
│   ├── preprocessor.py         # StandardScaler + 49-column alignment
│   ├── model_manager.py        # pickle save/load, model existence checks
│   ├── dataset_generator.py    # Synthetic bootstrap data generator
│   └── real_dataset_loader.py  # CICIDS2017 CSV → BENFET column mapping
├── reports/
│   ├── pdf_report.py           # ReportLab PDF generator
│   └── report_generator.py     # Legacy HTML report (Jinja2)
├── frontend/
│   ├── app/                    # Next.js 14 App Router pages
│   │   ├── globals.css         # Global color palette (Grape Dark theme)
│   │   └── analysis/[id]/      # Per-analysis forensic detail page
│   └── components/
│       ├── RecordsTable.js     # Main forensic records dashboard
│       └── UploadZone.js       # Drag/drop PCAP upload interface
├── data/
│   ├── training_data.csv       # Live RL training accumulator
│   └── fingerprints/           # Per-identity JSON behavioral fingerprints
├── models/                     # Saved model.pkl + scaler.pkl
└── obsidian_identities.db      # SQLite identity database
```

---

## License

Research & Academic Use. Not for production deployment without additional hardening.

---

*Built with Python · Flask · Next.js · scikit-learn · ReportLab · Scapy*
