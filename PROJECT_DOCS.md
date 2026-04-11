# The Obsidian Lens — Project Documentation

> A forensic-grade network behavioral analysis platform with real-time identity tracking, ML-based threat classification, and an analyst-facing dashboard.

---

## Project Overview

**Obsidian Lens** is a two-component application:
- **Backend**: Python/Flask REST API that ingests network traffic (live capture or PCAP upload), extracts 49 behavioral features per flow, classifies threats using a Random Forest model trained on real IDS data, and stores behavioral fingerprints in a SQLite identity database.
- **Frontend**: Next.js 14 dashboard that visualizes identities, health scores, recent analyses, XAI insights, and provides controls for live capture, feedback-based re-training, and identity management.

---

## Tech Stack

### Backend
| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| Framework | Flask (REST API, no templates) |
| ML | scikit-learn — `RandomForestClassifier` |
| Data Processing | pandas, numpy |
| Packet Parsing | Scapy (requires Npcap on Windows) |
| Identity Store | SQLite via `sqlite3` (standard library) |
| PDF Reports | ReportLab |
| CORS | Manual `after_request` headers |
| Threading | `threading.Lock` for dataset write safety |

### Frontend
| Component | Technology |
|-----------|------------|
| Framework | Next.js 14 (App Router) |
| Language | JavaScript (React) |
| Styling | Vanilla CSS Modules (`page.module.css`) |
| HTTP | `fetch()` (no axios) |
| Toast | `react-hot-toast` |
| Charts | (planned — not yet implemented) |

### DevOps
| Component | Details |
|-----------|---------|
| VCS | Git → GitHub (`aayushchavanke/Lens`) |
| Startup | `python app.py` (Flask) + `npm run dev` (Next.js) |
| Model Storage | `.pkl` files in `models/` (gitignored) |
| Dataset Storage | `datasets/real_world/` CSVs |

---

## Directory Structure

```
BENFET_fixed/
├── app.py                         # Flask backend — all API routes
├── config.py                      # Path constants, folder setup
├── requirements.txt
│
├── core/
│   ├── feature_extractor.py       # Extracts 49 behavioral features per flow
│   ├── identity_db.py             # SQLite identity CRUD + codename engine
│   ├── live_capture.py            # Scapy-based live packet capture
│   ├── pcap_parser.py             # Parses .pcap/.pcapng into flow dicts
│   ├── flow_analyzer.py           # High-level traffic statistics
│   └── topology_mapper.py         # Network graph (source→dest mapping)
│
├── ml/
│   ├── classifier.py              # RandomForest with predict_with_details()
│   ├── preprocessor.py            # StandardScaler + FEATURE_COLUMNS (49)
│   ├── real_dataset_loader.py     # Loads CICIDS2017 CSV → FEATURE_COLUMNS format
│   ├── model_manager.py           # save_model() / load_model() / model_exists()
│   ├── dataset_generator.py       # RETIRED — synthetic data, kept for reference
│   └── feature_weights.py         # (utility)
│
├── reports/
│   └── pdf_report.py              # ReportLab PDF generation
│
├── datasets/
│   └── real_world/
│       └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv  # 225k rows
│
├── data/
│   └── rl_feedback.csv            # Analyst-labelled flows (RL correction layer)
│
├── models/
│   ├── rf_behavioral_model.pkl    # Trained RF model
│   └── scaler.pkl                 # Fitted StandardScaler
│
├── frontend/
│   ├── app/
│   │   ├── page.js                # Main dashboard
│   │   └── page.module.css
│   └── components/
│       ├── HealthScore.js
│       ├── IdentityTable.js
│       └── UploadZone.js
│
└── obsidian_identities.db         # SQLite file (gitignored)
```

---

## Data Flow

### Mode 1 — PCAP Upload
```
User drops .pcap file
    → POST /api/upload         (save file, return analysis_id)
    → POST /api/analyze/<id>   (trigger pipeline)
         ↓
    pcap_parser.py             (parse raw packets → flows dict)
         ↓
    feature_extractor.py       (compute 49 behavioral features per flow)
         ↓
    preprocessor.transform()   (StandardScaler normalize)
         ↓
    classifier.predict_with_details()  (RF → label + confidence + is_malicious)
         ↓
    identity_db.upsert_identity()      (match or create behavioral identity)
         ↓
    LRU analysis cache + JSON response
         ↓
    Frontend dashboard auto-refresh (5s polling)
```

### Mode 2 — Live Capture
```
User clicks "Live Capture"
    → POST /api/capture/start  (Scapy sniff in background thread)
User clicks "Stop Capture"
    → POST /api/capture/stop   (stop + auto-save to .pcap)
    → triggers same pipeline as PCAP Upload above
```

### Mode 3 — Reinforcement Learning Feedback
```
Analyst selects an analysis + assigns confirmed profile label
    → POST /api/feedback/<analysis_id>
         ↓
    Re-extract features from PCAP
    Label all flows with analyst's label
         ↓
    Append to data/rl_feedback.csv
         ↓
    Reload: real_dataset (80k rows) + rl_feedback merged
    Retrain Random Forest from scratch
    Save new .pkl
```

---

## Machine Learning Model

### Algorithm
**Random Forest Classifier** (`sklearn.ensemble.RandomForestClassifier`)
- `n_estimators=100`
- `class_weight='balanced'` — handles class imbalance automatically
- `n_jobs=-1` — uses all CPU cores

### Feature Set — 49 Features (CICIDS2017-aligned)
All features are purely behavioral — no IP addresses, no port numbers.

| Category | Count | Features |
|----------|-------|---------|
| Flow Duration | 1 | `flow_duration` |
| Overall IAT | 4 | `iat_mean/std/min/max` |
| Forward IAT | 4 | `fwd_iat_mean/std/min/max` |
| Backward IAT | 4 | `bwd_iat_mean/std/min/max` |
| Active/Idle Times | 8 | `active_time_mean/std/min/max`, `idle_time_mean/std/min/max` |
| Directional Counts | 4 | `total_fwd/bwd_packets`, `total_fwd/bwd_bytes` |
| Fwd Packet Lengths | 4 | `fwd_pkt_len_mean/std/min/max` |
| Bwd Packet Lengths | 4 | `bwd_pkt_len_mean/std/min/max` |
| Packet Size Stats | 2 | `avg_packet_size`, `pkt_len_variance` |
| Volumetric | 4 | `flow_bytes/packets_per_sec`, `down_up_ratio`, `fwd_bwd_packet_ratio` |
| TCP Windows | 2 | `init_win_fwd`, `init_win_bwd` |
| Header Lengths | 2 | `fwd_header_len`, `bwd_header_len` |
| TCP Flags | 6 | `fin/syn/rst/psh/ack/urg_flag_count` |
| **Total** | **49** | |

> **Intentionally excluded from training** (still extracted for XAI display):
> TLS/JA3 features (11), SPL sequence (10), Burst metrics (4), TTL (2), DNS (1)
> These had no real values in CICIDS2017 — zero-filling them would harm prediction quality.

### Training Dataset — CICIDS2017
| Property | Value |
|----------|-------|
| File | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` |
| Total rows | 225,745 |
| Training cap | 100,000 rows (sampled randomly, `random_state=42`) |
| Class: BENIGN | 97,718 rows |
| Class: DDoS | 128,027 rows |
| Label mapping | BENIGN → `web_browser`, DDoS → `ddos_attack` |
| Source | Canadian Institute for Cybersecurity (CIC-IDS-2017) |

### Model Performance (Expected)
Random Forest on CICIDS2017 with these features typically achieves:
- Training accuracy: ~99.9%
- Cross-validation (5-fold): ~99.5–99.8%

---

## Identity Tracking System

### Database: `obsidian_identities.db` (SQLite)

**Tables**:
- `identities` — one row per behavioral fingerprint
- `identity_ips` — many IPs per identity (all IPs that identity has ever used)
- `identity_events` — audit log (blocked, unblocked, analysis events)

**Key columns**:
| Column | Type | Purpose |
|--------|------|---------|
| `codename` | TEXT | Human-readable label (e.g. `SwiftPhantom`) |
| `behavior_vector` | TEXT (JSON) | 10D float array for cross-device matching |
| `mac_address` | TEXT | Hardware fingerprint |
| `ja3_hash` | TEXT | TLS client fingerprint |
| `category` | TEXT | `white` (benign) or `black` (threat) |
| `is_blocked` | INTEGER | 0/1 — whether firewall rule is active |
| `confidence` | REAL | ML confidence score |
| `flow_count` | INTEGER | How many flows attribute to this identity |

### Codename Generation
Names are deterministically derived from behavior:
- **Adjective** ← `sum(behavior_vector[:5]) * 1000 % 20` → picks from TEMPORAL_ADJECTIVES list
- **Noun** ← `sum(behavior_vector[5:]) * 1000 % 20` → picks from VOLUMETRIC_NOUNS list
- Malicious: prefixed with `THREAT-` (e.g. `THREAT-BurstPhantom`)

### Cross-Device Matching
On every new flow, cosine similarity is computed against all stored behavior_vectors.
If similarity ≥ 0.85 → **reuse existing identity** (same codename, same DB row).
This enables tracking the same human across different devices, IPs, browsers, and OS reboots.

### Matching Priority
1. JA3 hash (strongest — cryptographic TLS fingerprint)
2. MAC address (hardware-level)
3. Cosine similarity ≥ 0.85 (behavioral cross-device)
4. IP address fallback (weakest)

---

## API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/upload` | Upload PCAP file |
| POST | `/api/analyze/<id>` | Run ML analysis pipeline |
| GET | `/api/analysis/<id>` | Get analysis result |
| DELETE | `/api/analysis/<id>` | Delete analysis record |
| GET | `/api/summary` | Dashboard health + recent analyses |
| GET | `/api/identities` | All identities (white + black lists) |
| POST | `/api/identities/<id>/block` | Add Windows Firewall rule |
| POST | `/api/identities/<id>/unblock` | Remove Windows Firewall rule |
| DELETE | `/api/identities/clear` | Wipe all identity records |
| POST | `/api/capture/start` | Start live Scapy capture |
| POST | `/api/capture/stop` | Stop capture + auto-analyze |
| GET | `/api/capture/status` | Capture stats (packets, elapsed) |
| POST | `/api/train` | Retrain model on CICIDS2017 + RL feedback |
| POST | `/api/feedback/<id>` | Submit analyst label → retrain |
| POST | `/api/feedback/bulk` | Batch feedback retrain |
| GET | `/api/report/<id>` | Download PDF forensic report |

---

## Blocking / Firewall (SOAR)
- Blocking runs `netsh advfirewall firewall add rule` silently via `subprocess.run()`
- **Must run Flask as Administrator** for netsh to work
- Blocks all IPs ever associated with the identity (not just MAC — Windows Firewall can't filter MAC)
- Unblocking removes the named rule by identity ID

---

## Known Pending Issues

1. **Duplicate upload toast** — UploadZone fires `onUploaded` twice in React strict-mode dev
2. **XAI insights dict** — still references removed TLS/SPL/burst features
3. **RL retraining is blocking** — loads full CSV on analyst feedback click; should be backgrounded
4. **More CICIDS data needed** — currently only DDoS+BENIGN; adding Botnet/PortScan CSV files will make classification richer
5. **Identity table** — should always prefer `.codename` field over legacy `.identity_label`
