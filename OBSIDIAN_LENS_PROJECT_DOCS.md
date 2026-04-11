# The Obsidian Lens 
**Advanced Behavioral Network Forensics & IPS Platform**
*(Formerly known as BENFET)*

## 1. Executive Summary
**The Obsidian Lens** is an enterprise-grade cybersecurity platform that shifts the paradigm of network security from static signature-matching to dynamic **Behavioral Fingerprinting**. 

Rather than relying on easily spoofed IP addresses, The Obsidian Lens identifies threat actors by analyzing the microscopic mathematical patterns of how they transfer data (behavioral dimensions). The platform successfully unmasks attackers using proxies or VPNs, flags them with Explainable AI (XAI), generates professional forensic reports, and actively terminates their connections via native host firewall bindings.

---

## 2. Core Technological Innovations

### 2.1. Behavioral Fingerprinting System
Instead of tracking logical addresses (IPs), the system builds a cross-device behavioral profile using **49 unique behavioral dimensions**. These include:
*   **Temporal Features:** Inter-Arrival Time (IAT) Mean/Variance, Active/Idle state ratios.
*   **Volumetric Features:** Down/Up Byte Ratios, Burst Packet counts, Flow Bytes per second.
*   **Spatial Features:** Forward/Backward average packet sizes.

### 2.2. Threat Detection Matrix
The core Machine Learning Engine is heavily trained on expansive datasets, categorizing flows into highly specific threat architectures instead of basic binary (Malicious/Benign) outputs.
**Classifiable Threats Include:**
*   DDoS / DoS (Hulk, GoldenEye, Slowloris, Slowhttptest)
*   Web Attacks (Brute Force, XSS, SQL Injection)
*   Botnets
*   PortScans
*   Infiltration Attempts
*   FTP/SSH Patator

### 2.3. Explainable AI (XAI) Forensics
The platform demystifies machine learning. When a packet is flagged, the XAI subsystem reverse-engineers the Artificial Intelligence's decision, extracting the **Top 3 most critical behavioral dimensions** (e.g., *Forward Packet Length Mean*) that indicted the connection. It translates this into plain-English tactical insights for human security analysts.

### 2.4. Active Intrusion Prevention System (IPS)
Obsidian Lens goes beyond passive monitoring. With full host-level integration, selecting "Block" on an identity triggers an automated subsystem that translates the behavioral identity to all historically associated IP addresses in the SQLite Database, and executes `netsh advfirewall` rules to autonomously block the attacker OS-wide.

---

## 3. Architecture & Tech Stack
*   **Frontend:** Next.js 14 / React (Bento-Grid layout with High-Contrast "Grape Dark Theme" aesthetics).
*   **Backend:** Python Flask powering a RESTful API.
*   **Traffic Ingestion:** Scapy / Npcap for promiscuous real-time live capture and static `.pcap` forensic parsing.
*   **Database:** SQLite using Write-Ahead Logging (WAL) for identities & Local JSON stores for ultra-fast behavioral caching.
*   **Machine Learning Compute:** Pandas, NumPy, Scikit-Learn.

---

## 4. Deep-Dive for AI / ML Engineers

This section covers the explicit technical pipeline of the underlying Machine Learning inference engine.

### 4.1. Dataset Engineering (CICIDS2017)
The foundational model operates on a custom reduction of the **Canadian Institute for Cybersecurity Intrusion Detection System dataset (CICIDS2017)**. 
*   **Feature Reduction:** The original 78 dimensions of the CICFlowMeter have been rigorously pruned via feature-importance extraction down to **49 hyper-optimized behavioral dimensions**. This removes noisy, correlated vectors (like literal IP addresses or timestamp strings) to mathematically guarantee the model learns *behavior* rather than static topological artifacts.
*   **Class Imbalance Handling:** The preprocessing pipeline manages the heavy imbalance between benign traffic (which dominates) and rare anomalies (e.g., Infiltration) by generating synthetic balanced training paradigms or applying weighted classes during model fit.

### 4.2. Model Architecture
The primary inference engine relies on an optimized **Random Forest Classifier** (`ml.classifier.BehavioralClassifier`).
*   **Why Random Forest?** Given the tabular and highly varied scale nature of network parameters (e.g., Window sizes bounding 0 to 65535 against Inter-Arrival Times rounding to micro-decimals), tree ensembles outperform Neural Networks on this specific task while requiring dramatically less inference CPU overhead. Crucially, Random Forests inherently support **Explainability (Feature Importances)**, allowing the XAI subsystem to pull `.feature_importances_` dynamically.
*   **Preprocessor Layer:** `ml.preprocessor.Preprocessor` standardizes continuous variables (Zero Mean, Unit Variance using `StandardScaler`) and applies `LabelEncoder` transformations to convert string threat categories (like `DoS Hulk`) into discrete algorithmic tensors.

### 4.3. Data Flow & Reinforcement Pipeline

**Pre-Inference Data Flow:**
1.  **Ingestion:** Raw `.pcap` byte-streams are intercepted by `core/pcap_parser.py`, which aggregates bidirectional packets into *Flows* using 5-tuple keys: `(SrcIP, DstIP, SrcPort, DstPort, Protocol)`.
2.  **Extraction:** `core/feature_extractor.py` recursively calculates the 49 statistical differentials (Std, Mean, Max, Min) across temporal and spatial gaps for both Forward and Backward directions.
3.  **Filtration:** All logical identifiers (Addresses, MACs, Payloads) are stripped, passing only an unsupervised 49-dimensional float tensor to the model.

**Evaluation & XAI Data Flow:**
1.  **Inference:** Data enters `predict_with_details()`. The RF Model outputs `is_malicious` flags, categorical `threat_type`, and a normalized `confidence` float.
2.  **Identity Matching:** The output vector is funneled to `identity_db.find_similar_identity()`. A **Cosine Similarity** threshold algorithm maps the 49-D vector against cached `.json` identity fingerprints. If `CosineSim > ~0.85`, the traffic is formally attributed to an existing persistent Identity payload, unmasking IP hopping.
3.  **Explainability:** The exact features driving that specific algorithmic tree split are exported as actionable insights for the dashboard payload (`explanations = [...]`).

**Reinforcement Learning (Continuous Feedback Loop):**
Unlike static ML systems, Obsidian Lens supports analyst reinforcement.
*   The human operator can select misclassified forensic records and submit the corrected ground-truth labels back to `/api/rl/feedback`.
*   The system executes an automated sliding-window retrain, replacing the oldest 5,000 dataset rows with the newly labeled data streams.
*   `classifier.train()` is automatically invoked in the background, hot-swapping the newly adjusted weight matrix into the live predictive funnel using `pickle` object-swapping inside `model_manager.py` without dropping running web processes.

---

## 5. Value Proposition (For Presentation/PPT)
*   **Blindspot Elimination:** Standard Firewalls block IPs; Obsidian Lens blocks *Humans/Bots behavior*, rendering VPN masking useless.
*   **Military-Grade Aesthetics & UX:** Designed for high-stress security operations centers with clear visual tagging (`[VPN]`, `[OK]`, `[!]`).
*   **No Black-Box AI:** All AI detection paths are reverse-engineered into human text, preserving legal and analytical integrity for audits.
*   **Zero to Fix:** One-click transition from forensics intelligence -> active network drop.
*   **Adaptive Intelligence:** Sub-second continuous active learning directly from analyst UI feedback loops.
