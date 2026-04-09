# Obsidian Lens - Troubleshooting Manifest

## Test Scenario Assessments

**Test Scenario 1: Identity Aggregation (De-Duplication)**
- **Result:** Pass. The system effectively aggregates multiple IPs into a single unified Threat entity based on MAC address matching. `upsert_identity` successfully updates existing identities without duplicating them and correctly updates the child table `identity_ips` with the rotated IP addresses.

**Test Scenario 2: Reinforcement Learning Batch Pipeline**
- **Result:** Conditional Pass / Potential Crash. The backend `/api/feedback/bulk` attempts to mitigate race conditions by combining features and appending to the CSV precisely once in the same thread. However, there is no file locking implemented when reading or appending to `training_data.csv`. If multiple analysts trigger `Auto-Train` simultaneously or a single analyst triggers it while an automated ingestion is happening, it will inevitably trigger CSV file-lock crashes and corrupted dataset appending.

**Test Scenario 3: Windows Firewall SOAR Execution**
- **Result:** Critical Error. The backend attempts to execute elevated Windows `netsh` firewall powershell commands (`Start-Process powershell -Verb RunAs`). Since this is a Flask web app running on a backend (potentially headless or non-interactive), an interactive UAC prompt will cause the subprocess to hang indefinitely or fail silently if no active desktop session can interact with the UAC dialogue.

**Test Scenario 4: Explainable AI Matrix Rendering**
- **Result:** Failure. When generating XAI insights, the system iterates over `XAI_INSIGHTS_DICT`. The dictionary only maps basic temporal and spatial features. It completely lacks mappings for encrypted features, notably `tls_cipher_entropy`. The test output correctly falls back to "The neural network identified extreme structural variance...", failing to provide the requested human-readable forensic sentence for `tls_cipher_entropy`.

---

## Top 5 Critical Production Errors & Solutions

### 1. UAC Prompt Hang during Firewall SOAR Execution
- **Error:** When an analyst clicks "Quarantine Entity" or "Unblock", the system invokes a PowerShell subprocess with `-Verb RunAs`. In a production environment running as a service, the UAC prompt has no interactive desktop to display on, causing the backend thread to hang indefinitely and block execution.
- **Solution:** Do not invoke interactive UAC prompts via web requests. The Flask backend should be deployed and run under an account that already possesses administrative privileges (e.g., a dedicated service account running the Python app as Admin). Remove `-Verb RunAs` and execute standard `subprocess.run(['netsh', 'advfirewall', ...])` natively from the pre-elevated Python environment.

### 2. Race Conditions & Data Corruption in Batch Retraining
- **Error:** Triggering model retraining or bulk feedback writes directly to `training_data.csv` using pandas `to_csv(mode='a')`. Without file locking, concurrent retraining requests or background dataset ingestion will corrupt the CSV or crash with `PermissionError` file-lock errors.
- **Solution:** Implement process-safe file locking. Utilize a library like `filelock` to wrap all reads, appends, and writes to `training_data.csv` in `app.py`. E.g., `with FileLock("data/training_data.csv.lock"): df.to_csv(...)`. Alternatively, migrate the training dataset to the robust SQLite database which handles concurrent transactions inherently.

### 3. Missing XAI Feature Explanations (e.g., TLS Entropy)
- **Error:** The XAI matrix mapping (`XAI_INSIGHTS_DICT`) lacks translations for several critical neural network features, including `tls_cipher_entropy`, leading to generic, non-insightful fallback text.
- **Solution:** Update `XAI_INSIGHTS_DICT` in `app.py` to include mappings for the remaining 78 parameters. Specifically add: `'tls_cipher_entropy': 'High TLS cryptography entropy suggests masking software or anomalous encryption wrappers attempting to evade deep packet inspection.'`

### 4. Unhandled scapy Installation Dependencies in Production
- **Error:** The `pcap_parser.py` explicitly throws `RuntimeError("scapy library is required...")` if `SCAPY_AVAILABLE` is false. Scapy has underlying OS-level dependencies (like `libpcap` on Linux or `Npcap` on Windows) that `requirements.txt` (`pip install scapy`) alone does not satisfy. Without these, live capture and PCAP ingestion will abruptly fail.
- **Solution:** Ensure the deployment documentation clearly instructs operators to install OS-level dependencies prior to startup. On Linux: `apt-get install libpcap-dev`. On Windows: `Install Npcap in WinPcap API-compatible mode`. Add a pre-flight OS dependency check in `app.py`'s `auto_initialize_system()`.

### 5. Memory Leak in Unbounded XAI Analysis Caching
- **Error:** The `analysis_cache` dictionary in `app.py` infinitely stores PCAP analysis results in memory (`save_analysis`, `get_analysis`). While `delete_analysis_record` removes individual entries, standard operation continually grows the cache. Large PCAP JSON reports will eventually trigger an Out-Of-Memory (OOM) crash in production.
- **Solution:** Implement cache bounding. Limit the in-memory `analysis_cache` to a maximum number of entries (e.g., using `functools.lru_cache` or a custom LRU eviction strategy). Old analysis should strictly be read back from the `ANALYSIS_FOLDER` disk storage when requested, keeping the RAM footprint minimal.
