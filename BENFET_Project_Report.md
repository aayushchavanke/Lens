# The Obsidian Lens - Comprehensive Software Engineering & System Design Report

## 1. Executive Summary & Tool Purpose
The Obsidian Lens is a **minimalistic, professional-grade network forensic tool** engineered specifically for security operations centers (SOC) and network administrators. Stripping away unnecessary noise, the tool focuses on an intuitive workflow and powerful backend analysis. Forensics professionals are presented with a clean interface featuring two core ingestion options (Live Capture and PCAP Upload) to passively monitor environments or conduct retrospective forensic analysis. 

## 2. Core Operational Modules
1. **Ingestion Engine**: Supports robust multi-threaded live packet sniffing off hardware NICs using Scapy/Npcap, as well as parsing historic `.pcap`/`.pcapng` files.
2. **Feature Extraction Pipeline**: Aggregates packets into bidirectional flows using transport layer tuples and extracts deep behavioral metrics.
3. **Machine Learning Classifier**: Normalizes data via a pre-fit `scaler.pkl` and infers threat severity utilizing a Weighted Random Forest model (`classifier.pkl`).
4. **Cloud Database Fingerprinting**: Persistently stores network identities, mapping multiple IP addresses to consistent users via MAC anchoring and JA3 TLS hashing.
5. **Access Control (Block/Unblock)**: Provides network administrators the programmatic rights to block malicious identities from re-entering the network layout.

---

## 3. The 78-Parameter Behavioral Analysis Engine
To circumvent the limitations of Deep Packet Inspection (DPI) against encrypted traffic, the system aggressively analyzes traffic over exactly **78 distinct behavioral parameters**. 

**Applied Feature Weighting (`ml/feature_weights.py`)**: 
By default, the behavioral analysis engine applies **Uniform Weighting (Weight: 1.0)** across all 78 parameters. This prevents algorithmic bias toward highly erratic variables (like bulk bytes) and allows the normalized Random Forest to accurately parse subtle heartbeat patterns. Security professionals can optionally write domain-specific weights to customize threat sensitivity.

### Exhaustive List of Extracted Parameters:

**Category 1: Temporal Features (21 Parameters)**
*Focuses on timing, delays, and state transitions to identify automated beaconing.*
- `flow_duration` (Weight: 1.0)
- `iat_mean`, `iat_std`, `iat_min`, `iat_max` (Inter-Arrival Times - Weight: 1.0 each)
- `fwd_iat_mean`, `fwd_iat_std`, `fwd_iat_min`, `fwd_iat_max` (Forward IAT - Weight: 1.0 each)
- `bwd_iat_mean`, `bwd_iat_std`, `bwd_iat_min`, `bwd_iat_max` (Backward IAT - Weight: 1.0 each)
- `active_time_mean`, `active_time_std`, `active_time_min`, `active_time_max` (Weight: 1.0 each)
- `idle_time_mean`, `idle_time_std`, `idle_time_min`, `idle_time_max` (Weight: 1.0 each)

**Category 2: Spatial Features (24 Parameters)**
*Measures packet sizes, asymmetry, and sequences to spot payload exfiltration.*
- `total_fwd_packets`, `total_bwd_packets` (Weight: 1.0 each)
- `total_fwd_bytes`, `total_bwd_bytes` (Weight: 1.0 each)
- `fwd_pkt_len_mean`, `fwd_pkt_len_std`, `fwd_pkt_len_min`, `fwd_pkt_len_max` (Weight: 1.0 each)
- `bwd_pkt_len_mean`, `bwd_pkt_len_std`, `bwd_pkt_len_min`, `bwd_pkt_len_max` (Weight: 1.0 each)
- `avg_packet_size`, `pkt_len_variance` (Weight: 1.0 each)
- `spl_1` through `spl_10` (Sequence of Packet Lengths for the first 10 packets - Weight: 1.0 each)

**Category 3: Volumetric & Directional Features (8 Parameters)**
*Calculates transfer rates, ratios, and burst logic typical of malware uploads.*
- `flow_bytes_per_sec`, `flow_packets_per_sec` (Weight: 1.0 each)
- `down_up_ratio`, `fwd_bwd_packet_ratio` (Weight: 1.0 each)
- `burst_count`, `burst_avg_size`, `burst_avg_duration`, `burst_total_packets` (Weight: 1.0 each)

**Category 4: TCP/IP & Flag Features (14 Parameters)**
*Monitors transport layer handshakes, window limits, and DNS interaction limits.*
- `init_win_fwd`, `init_win_bwd` (Weight: 1.0 each)
- `fwd_header_len`, `bwd_header_len` (Weight: 1.0 each)
- `fin_flag_count`, `syn_flag_count`, `rst_flag_count` (Weight: 1.0 each)
- `psh_flag_count`, `ack_flag_count`, `urg_flag_count` (Weight: 1.0 each)
- `ttl_mean`, `ttl_std` (Weight: 1.0 each)
- `dns_query_count`, `total_packets` (Weight: 1.0 each)

**Category 5: Encrypted / TLS Features (11 Parameters)**
*Extracts cryptographic headers to profile actor intent without breaking encryption.*
- `tls_num_ciphersuites`, `tls_num_extensions` (Weight: 1.0 each)
- `tls_handshake_duration`, `tls_version`, `tls_has_sni` (Weight: 1.0 each)
- `tls_ext_lengths_mean`, `tls_ext_lengths_std` (Weight: 1.0 each)
- `tls_cipher_entropy`, `tls_is_resumed` (Weight: 1.0 each)
- `tls_has_ja3`, `tls_ja3_numeric` (Weight: 1.0 each)

---

## 4. User Categorization & Threat Intelligence
Based on the 78-parameter pipeline, the tool automatically profiles and categorizes every identity into two primary groups:

### Normal Users (White Entities)
Benign actors operating within expected baseline thresholds. These identities may rotate through dozens of IP addresses, but their Behavioral Fingerprint (e.g., standard web browsing, database syncing) remains classified as White. These users are permitted free network functionality.

### Malicious Users (Black Entities)
Threat actors, compromised internal networks, or severe policy violators. Once flagged as Black, the system cross-references the 78 features to further categorize the explicit threat type:
- **Ransomware Operators**: Identified by massive asymmetric byte flows and specific burst durations.
- **Advanced Persistent Threats (APT)**: Identified by perfectly uniform, low-volume `idle_time` patterns indicating Command & Control (C2) beaconing.
- **VPN-Masked Exfiltrators**: Identified by packet padding markers and continuous tunneling overhead.

---

## 5. Cloud Fingerprinting & Endpoint Access Control
The Obsidian Lens operates with persistent memory.
- **Cloud / Database Storage**: The behavioral fingerprints and extracted identities (MAC + JA3 hashes) of both Normal and Malicious users are instantly stored in the connected Cloud Database (via PostgreSQL/SQLite).
- **Persistent Recognition**: If a Malicious user attempts to re-enter the network operating from an entirely new IP address, the system identifies the returning behavioral and TLS fingerprint instantly.
- **Professional Rights (Block & Unblock)**: The forensics professional holds absolute authority over network access. Through the UI, professionals actively flip identities to **Block** (preventing network entry at the firewall/IDS level) or **Unblock** if an investigation successfully clears their status.

---

## 6. Minimalistic Professional Dashboard UI
The Next.js 14 frontend is designed specifically for high-stress SOC environments, utilizing dark-mode aesthetics to reduce cognitive-load.
- **Network Health Overview**: A master metric summarizing the real-time security posture of the monitored interface based on the ratio of active White to Black users.
- **Categorization Tables**: Clearly separated sections detailing 'White' (Normal) identities and 'Black' (Malicious/Threat) users in clean data-grids.
- **Quick Action Toggles**: One-click toggles mapped to each User Identity that immediately push `Block` or `Unblock` instructions to the backend API.

---

## 7. Complete System Data Flow
1. **Ingestion & Flow Formation**: Python/Scapy listeners ingest raw frames and map them to bidirectional flow tuples.
2. **Worker Pool Extraction**: A ThreadPoolExecutor simultaneously strips the active packets down to generate the 78-dimensional behavioral array (`core/feature_extractor.py`).
3. **Normalization**: The data runs through `scaler.pkl` to standardize all variance.
4. **Machine Learning Classifying/Weighting**: `classifier.pkl` (Weighted Random Forest) assesses the normalized vector and outputs a class label.
5. **Database Syncing**: The entity's IP, MAC, TLS Signature, and Prediction are sent to the Cloud Database layer to update the tracked User Identity.
6. **Action & Response**: The professional views the Network Health dashboard and issues `Block` commands via the API.

---

## 8. Future Enterprise Expansion Roadmap (Planned Integration)
To effectively scale this tool for large Managed Security Service Providers (MSSP) and enterprise forensic labs, the architecture naturally supports the following sophisticated integrations:

### 8.1 SIEM, SOAR, & Webhook Orchestration
Forensic tools must not operate in a vacuum. A direct Webhook/REST API output layer is planned. When the 78-parameter core tags an identity as 'Black', the platform will instantly dispatch an automated JSON alert payload to external SIEMs (Splunk, IBM QRadar) or SOAR platforms to initiate company-wide automated retaliation (e.g., automatically terminating an employee's Active Directory access upon Ransomware detection).

### 8.2 Hybrid Threat Intelligence Blacklisting (STIX/TAXII)
Prior to engaging the computationally heavy Machine Learning pipeline, an early-rejection 'Blacklist' loop is planned. By pulling real-time STIX/TAXII feeds from MITRE or the NSA, the platform will instantly cross-reference incoming IP arrays and TLS JA3 signatures with known zero-day attackers. This allows for lightning-fast signature blocking, saving the deep 78-feature behavioral compute *exclusively* for finding completely unknown stealth actors. 

### 8.3 Smart PCAP Payload Truncation (Cost Optimization)
Forensic data storage is notoriously expensive. We plan to implement a Python-based truncation module that leverages the ML classification logic:
- If a flow is categorized as a **White User**, the system strips out the raw payload and saves exactly 64 bytes of headers.
- If a flow is categorized as a **Black User**, the system stores the FULL PCAP evidence.
This logic is projected to save enterprise companies millions in AWS S3 storage costs while unconditionally securing necessary legal forensic evidence.

### 8.4 Multi-Tenancy & Role-Based Access Control (RBAC)
To support usage by multiple professional responder tiers, the platform's API and DB will transition to strict Multi-Tenancy. 
- *L1 Analysts* are granted Read-Only access to the Network Health Dashboards.
- *L3 Incident Responders* possess the JWT-authenticated permissions to execute the absolute `Block` commands and pull raw PCAP data across segregated client database structures.

---

## 9. Technology Stack
- **Frontend / Dashboard**: Next.js 14, React.js, Tailwind CSS (Bento-style Minimal UI).
- **Backend API Engine**: Python 3.10+, Flask>=3.0.0.
- **Network Processing Core**: Scapy (Backend Packet capture & PCAP parsing).
- **Database / Infrastructure**: Cloud Relational Database (SQLite local / PostgreSQL remote).
- **Machine Learning Layer**: Scikit-Learn (Random Forest classifiers), Pandas, NumPy.
