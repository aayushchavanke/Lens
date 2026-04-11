"""
BENFET Core - Feature Extractor (v2)
Computes comprehensive behavioral feature vectors from parsed flow data.
Extracts 90+ raw signals, condensed to 49 ML features used for classification:
  1. Temporal (21 — timing, IAT statistics, active/idle periods)
  2. Spatial (12 — forward/backward packet length statistics)
  3. Volumetric & Directional (8 — rates, ratios, burst detection)
  4. TCP/IP & Flags (8 — window sizes, header lengths, all 6 flag counts)

Additional signals (extracted but NOT used by classifier — display/XAI only):
  - TLS fingerprinting (JA3, ciphersuites, extensions, handshake duration)
  - Sequence of Packet Lengths (SPL), TTL, DNS packet counts, Burst metrics

IMPORTANT: IP addresses are NEVER used as features.
The classifier works purely on behavioral metadata, enabling behavior-based
fingerprinting that persists even when a device changes its IP address.
"""

import numpy as np
import pandas as pd
import math
from config import BURST_THRESHOLD_SECONDS, MIN_BURST_PACKETS


def extract_features(parsed_data, max_workers=4):
    """
    Extract comprehensive behavioral feature vectors from parsed PCAP data.

    Args:
        parsed_data: Output from pcap_parser.parse_pcap()
        max_workers: Number of threads to use for parallel feature extraction

    Returns:
        pandas DataFrame where each row is a flow's behavioral fingerprint.
        IPs are included as identifiers only (never as ML features).
    """
    from concurrent.futures import ThreadPoolExecutor

    flows = parsed_data['raw_flows']
    tls_flows = parsed_data.get('tls_flows', {})
    feature_rows = []

    def process_flow(item):
        flow_key, packets = item
        if len(packets) < 1:
            return None
        return _compute_flow_features(flow_key, packets, tls_flows)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(process_flow, flows.items())

    for res in results:
        if res is not None:
            feature_rows.append(res)

    if not feature_rows:
        return pd.DataFrame()

    df = pd.DataFrame(feature_rows)
    return df


def _safe_stats(arr):
    """Compute mean, std, min, max for an array, returning zeros if empty."""
    if len(arr) == 0:
        return 0, 0, 0, 0
    return float(np.mean(arr)), float(np.std(arr)), float(np.min(arr)), float(np.max(arr))


def _compute_flow_features(flow_key, packets, tls_flows):
    """Compute all 80+ behavioral features for a single flow."""
    src_ip, dst_ip = flow_key[0], flow_key[1]
    all_timestamps = sorted([p['timestamp'] for p in packets])
    all_sizes = [p['packet_length'] for p in packets]

    # ─── Split by direction ──────────────────────────────────────────────

    fwd_packets = [p for p in packets if p.get('is_forward', True)]
    bwd_packets = [p for p in packets if not p.get('is_forward', True)]

    fwd_sizes = [p['packet_length'] for p in fwd_packets]
    bwd_sizes = [p['packet_length'] for p in bwd_packets]

    fwd_timestamps = sorted([p['timestamp'] for p in fwd_packets]) if fwd_packets else []
    bwd_timestamps = sorted([p['timestamp'] for p in bwd_packets]) if bwd_packets else []

    # ─── Inter-Arrival Times ─────────────────────────────────────────────

    all_iats = np.diff(all_timestamps) if len(all_timestamps) > 1 else np.array([])
    fwd_iats = np.diff(fwd_timestamps) if len(fwd_timestamps) > 1 else np.array([])
    bwd_iats = np.diff(bwd_timestamps) if len(bwd_timestamps) > 1 else np.array([])

    # ─── Active / Idle Times ─────────────────────────────────────────────

    active_times, idle_times = _compute_active_idle(all_timestamps, BURST_THRESHOLD_SECONDS)

    # ─── Burst Detection ─────────────────────────────────────────────────

    bursts = _detect_bursts(all_timestamps)

    # ─── Flow Duration ───────────────────────────────────────────────────

    duration = all_timestamps[-1] - all_timestamps[0] if len(all_timestamps) > 1 else 0.0001

    # ─── Sequence of Packet Lengths (SPL) — first 10 ─────────────────────

    spl = all_sizes[:10] + [0] * max(0, 10 - len(all_sizes))

    # ─── Header & Window Statistics ──────────────────────────────────────

    fwd_header_lens = [p['header_len'] for p in fwd_packets]
    bwd_header_lens = [p['header_len'] for p in bwd_packets]

    # Initial TCP window = window of first packet in each direction
    init_win_fwd = fwd_packets[0]['tcp_window_size'] if fwd_packets else 0
    init_win_bwd = bwd_packets[0]['tcp_window_size'] if bwd_packets else 0

    # ─── TLS Features ────────────────────────────────────────────────────

    tls_key = str(flow_key)
    tls_data = tls_flows.get(tls_key, {})
    tls_ciphersuites = tls_data.get('ciphersuites', [])
    tls_extensions = tls_data.get('extensions', [])
    tls_ext_lengths = tls_data.get('ext_lengths', []) if isinstance(tls_data, dict) else []

    # Shannon entropy of ciphersuite list
    cipher_entropy = _shannon_entropy(tls_ciphersuites)

    # ─── Stat helpers ────────────────────────────────────────────────────

    iat_mean, iat_std, iat_min, iat_max = _safe_stats(all_iats)
    fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max = _safe_stats(fwd_iats)
    bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max = _safe_stats(bwd_iats)
    active_mean, active_std, active_min, active_max = _safe_stats(active_times)
    idle_mean, idle_std, idle_min, idle_max = _safe_stats(idle_times)
    fwd_len_mean, fwd_len_std, fwd_len_min, fwd_len_max = _safe_stats(fwd_sizes)
    bwd_len_mean, bwd_len_std, bwd_len_min, bwd_len_max = _safe_stats(bwd_sizes)
    ext_len_mean, ext_len_std, _, _ = _safe_stats(tls_ext_lengths) if tls_ext_lengths else (0, 0, 0, 0)

    # ═════════════════════════════════════════════════════════════════════
    #  BUILD FEATURE VECTOR
    # ═════════════════════════════════════════════════════════════════════

    features = {
        # ── Identifiers (NOT used for ML — only for display/tracking) ────
        'flow_key': f"{src_ip}:{flow_key[2]}<->{dst_ip}:{flow_key[3]}",
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': flow_key[4],

        # ═══ 1. TEMPORAL FEATURES (20) ═══════════════════════════════════

        # Flow duration
        'flow_duration': duration,

        # Overall IAT statistics
        'iat_mean': iat_mean,
        'iat_std': iat_std,
        'iat_min': iat_min,
        'iat_max': iat_max,

        # Forward IAT statistics
        'fwd_iat_mean': fwd_iat_mean,
        'fwd_iat_std': fwd_iat_std,
        'fwd_iat_min': fwd_iat_min,
        'fwd_iat_max': fwd_iat_max,

        # Backward IAT statistics
        'bwd_iat_mean': bwd_iat_mean,
        'bwd_iat_std': bwd_iat_std,
        'bwd_iat_min': bwd_iat_min,
        'bwd_iat_max': bwd_iat_max,

        # Active time statistics
        'active_time_mean': active_mean,
        'active_time_std': active_std,
        'active_time_min': active_min,
        'active_time_max': active_max,

        # Idle time statistics
        'idle_time_mean': idle_mean,
        'idle_time_std': idle_std,
        'idle_time_min': idle_min,
        'idle_time_max': idle_max,

        # ═══ 2. SPATIAL FEATURES (24) ════════════════════════════════════

        # Directional packet counts
        'total_fwd_packets': len(fwd_packets),
        'total_bwd_packets': len(bwd_packets),

        # Directional byte totals
        'total_fwd_bytes': sum(fwd_sizes) if fwd_sizes else 0,
        'total_bwd_bytes': sum(bwd_sizes) if bwd_sizes else 0,

        # Forward packet length statistics
        'fwd_pkt_len_mean': fwd_len_mean,
        'fwd_pkt_len_std': fwd_len_std,
        'fwd_pkt_len_min': fwd_len_min,
        'fwd_pkt_len_max': fwd_len_max,

        # Backward packet length statistics
        'bwd_pkt_len_mean': bwd_len_mean,
        'bwd_pkt_len_std': bwd_len_std,
        'bwd_pkt_len_min': bwd_len_min,
        'bwd_pkt_len_max': bwd_len_max,

        # Overall size statistics
        'avg_packet_size': float(np.mean(all_sizes)),
        'pkt_len_variance': float(np.var(all_sizes)),

        # Sequence of Packet Lengths (first 10 packets)
        'spl_1': spl[0], 'spl_2': spl[1], 'spl_3': spl[2], 'spl_4': spl[3],
        'spl_5': spl[4], 'spl_6': spl[5], 'spl_7': spl[6], 'spl_8': spl[7],
        'spl_9': spl[8], 'spl_10': spl[9],

        # ═══ 3. VOLUMETRIC & DIRECTIONAL FEATURES (8) ════════════════════

        # Transfer rates
        'flow_bytes_per_sec': sum(all_sizes) / max(duration, 0.0001),
        'flow_packets_per_sec': len(packets) / max(duration, 0.0001),

        # Ratios
        'down_up_ratio': sum(bwd_sizes) / max(sum(fwd_sizes), 1) if fwd_sizes else 0,
        'fwd_bwd_packet_ratio': len(fwd_packets) / max(len(bwd_packets), 1),

        # Burst behavior
        'burst_count': len(bursts),
        'burst_avg_size': float(np.mean([b['packet_count'] for b in bursts])) if bursts else 0,
        'burst_avg_duration': float(np.mean([b['duration'] for b in bursts])) if bursts else 0,
        'burst_total_packets': sum(b['packet_count'] for b in bursts),

        # ═══ 4. TCP/IP & FLAG FEATURES (14) ══════════════════════════════

        # Initial TCP window sizes
        'init_win_fwd': init_win_fwd,
        'init_win_bwd': init_win_bwd,

        # Header lengths per direction
        'fwd_header_len': sum(fwd_header_lens) if fwd_header_lens else 0,
        'bwd_header_len': sum(bwd_header_lens) if bwd_header_lens else 0,

        # All 6 TCP flag counts
        'fin_flag_count': sum(1 for p in packets if 'F' in p.get('flags', '')),
        'syn_flag_count': sum(1 for p in packets if 'S' in p.get('flags', '')),
        'rst_flag_count': sum(1 for p in packets if 'R' in p.get('flags', '')),
        'psh_flag_count': sum(1 for p in packets if 'P' in p.get('flags', '')),
        'ack_flag_count': sum(1 for p in packets if 'A' in p.get('flags', '')),
        'urg_flag_count': sum(1 for p in packets if 'U' in p.get('flags', '')),

        # TTL statistics
        'ttl_mean': float(np.mean([p['ttl'] for p in packets])),
        'ttl_std': float(np.std([p['ttl'] for p in packets])),

        # DNS
        'dns_query_count': sum(1 for p in packets if p.get('has_dns', False)),

        # Total packets (overall)
        'total_packets': len(packets),

        # ═══ 5. ENCRYPTED / TLS FEATURES (10) ════════════════════════════

        # TLS ciphersuite count
        'tls_num_ciphersuites': len(tls_ciphersuites),

        # TLS extension count
        'tls_num_extensions': len(tls_extensions),

        # TLS handshake duration
        'tls_handshake_duration': tls_data.get('handshake_duration_ms', 0) if isinstance(tls_data, dict) else 0,

        # TLS version (encoded numeric: 0=none, 1=SSL3, 2=TLS1.0, 3=TLS1.1, 4=TLS1.2, 5=TLS1.3)
        'tls_version': _encode_tls_version(tls_data.get('tls_version', '') if isinstance(tls_data, dict) else ''),

        # TLS has SNI extension (type 0)
        'tls_has_sni': 1 if 0 in tls_extensions else 0,

        # Extension length statistics
        'tls_ext_lengths_mean': ext_len_mean,
        'tls_ext_lengths_std': ext_len_std,

        # Ciphersuite entropy
        'tls_cipher_entropy': cipher_entropy,

        # Session resumed (SessionTicket extension type 35)
        'tls_is_resumed': 1 if 35 in tls_extensions else 0,

        # Has JA3 fingerprint (presence indicator)
        'tls_has_ja3': 1 if tls_data.get('ja3') else 0,

        # JA3 hash numeric encoding (first 8 hex chars → int for ML)
        'tls_ja3_numeric': _ja3_to_numeric(tls_data.get('ja3', '') if isinstance(tls_data, dict) else ''),
    }

    return features


# ─── Active / Idle Time Detection ────────────────────────────────────────

def _compute_active_idle(sorted_timestamps, threshold):
    """
    Compute active and idle time periods.
    Active = consecutive packets with IAT < threshold.
    Idle = gaps between active periods (IAT >= threshold).
    """
    if len(sorted_timestamps) < 2:
        return [], []

    active_times = []
    idle_times = []
    active_start = sorted_timestamps[0]
    prev_ts = sorted_timestamps[0]

    for i in range(1, len(sorted_timestamps)):
        iat = sorted_timestamps[i] - prev_ts
        if iat >= threshold:
            # End of active period
            active_dur = prev_ts - active_start
            if active_dur > 0:
                active_times.append(active_dur)
            # Idle gap
            idle_times.append(iat)
            active_start = sorted_timestamps[i]
        prev_ts = sorted_timestamps[i]

    # Final active period
    final_active = prev_ts - active_start
    if final_active > 0:
        active_times.append(final_active)

    return active_times, idle_times


# ─── Burst Detection ────────────────────────────────────────────────────

def _detect_bursts(sorted_timestamps):
    """Detect packet bursts based on inter-arrival time threshold."""
    if len(sorted_timestamps) < MIN_BURST_PACKETS:
        return []

    bursts = []
    current_burst_start_time = sorted_timestamps[0]
    current_burst_count = 1

    for i in range(1, len(sorted_timestamps)):
        iat = sorted_timestamps[i] - sorted_timestamps[i - 1]
        if iat <= BURST_THRESHOLD_SECONDS:
            current_burst_count += 1
        else:
            if current_burst_count >= MIN_BURST_PACKETS:
                bursts.append({
                    'start_time': current_burst_start_time,
                    'end_time': sorted_timestamps[i - 1],
                    'duration': sorted_timestamps[i - 1] - current_burst_start_time,
                    'packet_count': current_burst_count,
                })
            current_burst_start_time = sorted_timestamps[i]
            current_burst_count = 1

    if current_burst_count >= MIN_BURST_PACKETS:
        bursts.append({
            'start_time': current_burst_start_time,
            'end_time': sorted_timestamps[-1],
            'duration': sorted_timestamps[-1] - current_burst_start_time,
            'packet_count': current_burst_count,
        })

    return bursts


# ─── Utility Functions ──────────────────────────────────────────────────

def _shannon_entropy(values):
    """Compute Shannon entropy of a list of values."""
    if not values:
        return 0
    total = len(values)
    from collections import Counter
    counts = Counter(values)
    entropy = 0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _encode_tls_version(version_str):
    """Encode TLS version string to numeric value."""
    mapping = {
        'SSL 3.0': 1, 'TLS 1.0': 2, 'TLS 1.1': 3, 'TLS 1.2': 4, 'TLS 1.3': 5,
    }
    return mapping.get(version_str, 0)


def _ja3_to_numeric(ja3_hash):
    """Convert first 8 hex chars of JA3 hash to a numeric value for ML."""
    if not ja3_hash or len(ja3_hash) < 8:
        return 0
    try:
        return int(ja3_hash[:8], 16) / (16**8)  # Normalize to [0, 1]
    except ValueError:
        return 0


# Feature Columns for ML inference — matches ml/preprocessor.py FEATURE_COLUMNS exactly.
# 48 features — trimmed to only those genuinely present in CICIDS2017 real dataset.
# TLS, SPL, Burst, TTL, DNS features are still extracted above for display/XAI
# but are NOT used in the ML training/inference pipeline.
FEATURE_COLUMNS = [
    # Temporal — Flow Duration
    'flow_duration',
    # Overall IAT
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',
    # Forward IAT
    'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_min', 'fwd_iat_max',
    # Backward IAT
    'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_min', 'bwd_iat_max',
    # Active / Idle times
    'active_time_mean', 'active_time_std', 'active_time_min', 'active_time_max',
    'idle_time_mean',   'idle_time_std',   'idle_time_min',   'idle_time_max',
    # Spatial — directional packet/byte counts
    'total_fwd_packets', 'total_bwd_packets',
    'total_fwd_bytes',   'total_bwd_bytes',
    # Forward packet length stats
    'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'fwd_pkt_len_min', 'fwd_pkt_len_max',
    # Backward packet length stats
    'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'bwd_pkt_len_min', 'bwd_pkt_len_max',
    # Overall packet size statistics
    'avg_packet_size', 'pkt_len_variance',
    # Volumetric — transfer rates & ratios
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'down_up_ratio',      'fwd_bwd_packet_ratio',
    # TCP/IP — window sizes
    'init_win_fwd', 'init_win_bwd',
    # TCP/IP — header lengths
    'fwd_header_len', 'bwd_header_len',
    # TCP/IP — flag counts
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
    'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
]

assert len(FEATURE_COLUMNS) == 49, (
    f"FEATURE_COLUMNS length mismatch: expected 49, got {len(FEATURE_COLUMNS)}. "
    "Ensure preprocessor.py and feature_extractor.py are in sync."
)
