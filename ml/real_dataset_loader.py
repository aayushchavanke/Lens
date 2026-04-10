"""
BENFET ML - Real-World Dataset Loader
Loads and maps the CICIDS2017 dataset columns to BENFET's 78 FEATURE_COLUMNS.

The CICIDS dataset uses human-readable column names with spaces and mixed case.
This module provides column mapping and a clean loading pipeline.

Dataset: CIC-IDS-2017 (Canadian Institute for Cybersecurity)
Labels in DDoS file: BENIGN, DDoS
"""

import os
import numpy as np
import pandas as pd
from config import BASE_DIR

DATASET_DIR = os.path.join(BASE_DIR, 'datasets', 'real_world')

# ─── Column Mapping: CICIDS Column → BENFET FEATURE_COLUMN ───────────────────
# Maps the raw CICIDS2017 header names (stripped) to our internal snake_case names.

CICIDS_COLUMN_MAP = {
    'Flow Duration':           'flow_duration',

    # Overall IAT
    'Flow IAT Mean':           'iat_mean',
    'Flow IAT Std':            'iat_std',
    'Flow IAT Min':            'iat_min',
    'Flow IAT Max':            'iat_max',

    # Forward IAT
    'Fwd IAT Mean':            'fwd_iat_mean',
    'Fwd IAT Std':             'fwd_iat_std',
    'Fwd IAT Min':             'fwd_iat_min',
    'Fwd IAT Max':             'fwd_iat_max',

    # Backward IAT
    'Bwd IAT Mean':            'bwd_iat_mean',
    'Bwd IAT Std':             'bwd_iat_std',
    'Bwd IAT Min':             'bwd_iat_min',
    'Bwd IAT Max':             'bwd_iat_max',

    # Active / Idle times
    'Active Mean':             'active_time_mean',
    'Active Std':              'active_time_std',
    'Active Min':              'active_time_min',
    'Active Max':              'active_time_max',
    'Idle Mean':               'idle_time_mean',
    'Idle Std':                'idle_time_std',
    'Idle Min':                'idle_time_min',
    'Idle Max':                'idle_time_max',

    # Spatial — directional packet counts
    'Total Fwd Packets':       'total_fwd_packets',
    'Total Backward Packets':  'total_bwd_packets',

    # Spatial — directional byte counts (not directly in CICIDS as separate cols — use segment sizes * packet count)
    'Subflow Fwd Bytes':       'total_fwd_bytes',
    'Subflow Bwd Bytes':       'total_bwd_bytes',

    # Forward packet length stats
    'Fwd Packet Length Mean':  'fwd_pkt_len_mean',
    'Fwd Packet Length Std':   'fwd_pkt_len_std',
    'Fwd Packet Length Min':   'fwd_pkt_len_min',
    'Fwd Packet Length Max':   'fwd_pkt_len_max',

    # Backward packet length stats
    'Bwd Packet Length Mean':  'bwd_pkt_len_mean',
    'Bwd Packet Length Std':   'bwd_pkt_len_std',
    'Bwd Packet Length Min':   'bwd_pkt_len_min',
    'Bwd Packet Length Max':   'bwd_pkt_len_max',

    # Overall packet size
    'Average Packet Size':     'avg_packet_size',
    'Packet Length Variance':  'pkt_len_variance',

    # Volumetric
    'Flow Bytes/s':            'flow_bytes_per_sec',
    'Flow Packets/s':          'flow_packets_per_sec',
    'Down/Up Ratio':           'down_up_ratio',

    # TCP/IP
    'Init_Win_bytes_forward':  'init_win_fwd',
    'Init_Win_bytes_backward': 'init_win_bwd',
    'Fwd Header Length':       'fwd_header_len',
    'Bwd Header Length':       'bwd_header_len',
    'FIN Flag Count':          'fin_flag_count',
    'SYN Flag Count':          'syn_flag_count',
    'RST Flag Count':          'rst_flag_count',
    'PSH Flag Count':          'psh_flag_count',
    'ACK Flag Count':          'ack_flag_count',
    'URG Flag Count':          'urg_flag_count',

    # Label
    'Label':                   'label',
}

# ─── Label Mapping: CICIDS label → internal BENFET profile label ─────────────
LABEL_MAP = {
    'BENIGN':   'web_browser',   # Normal traffic
    'DDoS':     'ddos_attack',
    'DoS Hulk': 'ddos_attack',
    'DoS GoldenEye': 'ddos_attack',
    'DoS slowloris': 'ddos_attack',
    'DoS Slowhttptest': 'ddos_attack',
    'PortScan':  'port_scan',
    'Bot':       'botnet',
    'Infiltration': 'apt_exfiltration',
    'Web Attack – Brute Force': 'brute_force_ssh',
    'Web Attack – XSS': 'brute_force_ssh',
    'Web Attack – Sql Injection': 'brute_force_ssh',
    'FTP-Patator': 'brute_force_ssh',
    'SSH-Patator': 'brute_force_ssh',
    'Heartbleed': 'malware_c2',
}


def load_real_dataset(max_rows=None, label_map=None):
    """
    Load all CSV files from the real_world dataset folder, map columns to
    BENFET FEATURE_COLUMNS format, clean data, and return a training-ready DataFrame.

    Args:
        max_rows: Cap total rows (None = load all). Recommended: 100000 for fast training.
        label_map: Override the default LABEL_MAP.

    Returns:
        pd.DataFrame with exactly FEATURE_COLUMNS + 'label' columns.
    """
    from ml.preprocessor import FEATURE_COLUMNS

    if label_map is None:
        label_map = LABEL_MAP

    csv_files = [
        os.path.join(DATASET_DIR, f)
        for f in os.listdir(DATASET_DIR)
        if f.endswith('.csv')
    ]

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {DATASET_DIR}.\n"
            "Please add CICIDS2017 CSV files to datasets/real_world/"
        )

    print(f"[DATASET] Found {len(csv_files)} CSV files in {DATASET_DIR}")

    all_frames = []
    for csv_path in csv_files:
        print(f"  -> Loading: {os.path.basename(csv_path)}")
        df = pd.read_csv(csv_path, low_memory=False)

        # Strip whitespace from all column names
        df.columns = [c.strip() for c in df.columns]

        # Apply column mapping
        rename_map = {k: v for k, v in CICIDS_COLUMN_MAP.items() if k in df.columns}
        df = df.rename(columns=rename_map)

        all_frames.append(df)

    combined = pd.concat(all_frames, ignore_index=True)
    print(f"[DATASET] Raw combined shape: {combined.shape}")

    # Map labels
    if 'label' not in combined.columns and 'Label' in combined.columns:
        combined = combined.rename(columns={'Label': 'label'})

    combined['label'] = combined['label'].str.strip()
    combined['label'] = combined['label'].map(label_map).fillna('web_browser')

    print(f"[DATASET] Label distribution:\n{combined['label'].value_counts().to_dict()}")

    # fwd_bwd_packet_ratio — derivable from CICIDS data
    if 'fwd_bwd_packet_ratio' not in combined.columns:
        combined['fwd_bwd_packet_ratio'] = (
            combined['total_fwd_packets'] / combined['total_bwd_packets'].replace(0, 1)
        )

    # Keep only FEATURE_COLUMNS + label
    keep_cols = FEATURE_COLUMNS + ['label']
    combined = combined[[c for c in keep_cols if c in combined.columns]]

    # Ensure all FEATURE_COLUMNS are present (fill any remaining gaps with 0)
    for col in FEATURE_COLUMNS:
        if col not in combined.columns:
            print(f"  [WARN] Feature '{col}' still missing after mapping — filling with 0")
            combined[col] = 0

    # Clean: replace inf/NaN with 0
    combined[FEATURE_COLUMNS] = combined[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    combined[FEATURE_COLUMNS] = combined[FEATURE_COLUMNS].fillna(0)

    # Convert all feature columns to float
    combined[FEATURE_COLUMNS] = combined[FEATURE_COLUMNS].astype(float)

    # Optional row cap
    if max_rows and len(combined) > max_rows:
        combined = combined.sample(n=max_rows, random_state=42).reset_index(drop=True)
        print(f"[DATASET] Sampled down to {max_rows} rows for training.")

    print(f"[DATASET] Final training shape: {combined.shape}")
    return combined

