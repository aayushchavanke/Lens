import pandas as pd
import os
import argparse

# ═════════════════════════════════════════════════════════════════════════
#  CIC-IDS2017 -> OBSIDIAN LENS COLUMN MAPPER
# ═════════════════════════════════════════════════════════════════════════
# This script takes a raw, predefined CIC-IDS2017 MachineLearning CSV file,
# cleans the messy capitalization/spaces in its column names, maps them to
# the 78 strict programmatic identifiers needed by Obsidian Lens, and 
# overwrites the active training dataset.

CIC_IDS2017_MAPPING = {
    ' Destination Port': 'dst_port',
    ' Flow Duration': 'flow_duration',
    ' Total Fwd Packets': 'total_fwd_packets',
    ' Total Backward Packets': 'total_bwd_packets',
    'Total Length of Fwd Packets': 'total_fwd_bytes',
    ' Total Length of Bwd Packets': 'total_bwd_bytes',
    ' Fwd Packet Length Max': 'fwd_pkt_len_max',
    ' Fwd Packet Length Min': 'fwd_pkt_len_min',
    ' Fwd Packet Length Mean': 'fwd_pkt_len_mean',
    ' Fwd Packet Length Std': 'fwd_pkt_len_std',
    'Bwd Packet Length Max': 'bwd_pkt_len_max',
    ' Bwd Packet Length Min': 'bwd_pkt_len_min',
    ' Bwd Packet Length Mean': 'bwd_pkt_len_mean',
    ' Bwd Packet Length Std': 'bwd_pkt_len_std',
    'Flow Bytes/s': 'flow_bytes_per_sec',
    ' Flow Packets/s': 'flow_packets_per_sec',
    ' Flow IAT Mean': 'iat_mean',
    ' Flow IAT Std': 'iat_std',
    ' Flow IAT Max': 'iat_max',
    ' Flow IAT Min': 'iat_min',
    'Fwd IAT Total': 'fwd_iat_total',
    ' Fwd IAT Mean': 'fwd_iat_mean',
    ' Fwd IAT Std': 'fwd_iat_std',
    ' Fwd IAT Max': 'fwd_iat_max',
    ' Fwd IAT Min': 'fwd_iat_min',
    'Bwd IAT Total': 'bwd_iat_total',
    ' Bwd IAT Mean': 'bwd_iat_mean',
    ' Bwd IAT Std': 'bwd_iat_std',
    ' Bwd IAT Max': 'bwd_iat_max',
    ' Bwd IAT Min': 'bwd_iat_min',
    'Fwd PSH Flags': 'fwd_psh_flags',
    ' Bwd PSH Flags': 'bwd_psh_flags',
    ' Fwd URG Flags': 'fwd_urg_flags',
    ' Bwd URG Flags': 'bwd_urg_flags',
    ' Fwd Header Length': 'fwd_header_len',
    ' Bwd Header Length': 'bwd_header_len',
    'Fwd Packets/s': 'fwd_packets_per_sec',
    ' Bwd Packets/s': 'bwd_packets_per_sec',
    ' Min Packet Length': 'min_packet_length',
    ' Max Packet Length': 'max_packet_length',
    ' Packet Length Mean': 'packet_length_mean',
    ' Packet Length Std': 'packet_length_std',
    ' Packet Length Variance': 'pkt_len_variance',
    'FIN Flag Count': 'fin_flag_count',
    ' SYN Flag Count': 'syn_flag_count',
    ' RST Flag Count': 'rst_flag_count',
    ' PSH Flag Count': 'psh_flag_count',
    ' ACK Flag Count': 'ack_flag_count',
    ' URG Flag Count': 'urg_flag_count',
    ' CWE Flag Count': 'cwe_flag_count',
    ' ECE Flag Count': 'ece_flag_count',
    ' Down/Up Ratio': 'down_up_ratio',
    ' Average Packet Size': 'avg_packet_size',
    ' Avg Fwd Segment Size': 'avg_fwd_segment_size',
    ' Avg Bwd Segment Size': 'avg_bwd_segment_size',
    ' Fwd Header Length.1': 'fwd_header_len_1',
    'Fwd Avg Bytes/Bulk': 'fwd_avg_bytes_bulk',
    ' Fwd Avg Packets/Bulk': 'fwd_avg_packets_bulk',
    ' Fwd Avg Bulk Rate': 'fwd_avg_bulk_rate',
    ' Bwd Avg Bytes/Bulk': 'bwd_avg_bytes_bulk',
    'Bwd Avg Bulk Rate': 'bwd_avg_bulk_rate',
    'Subflow Fwd Packets': 'subflow_fwd_packets',
    ' Subflow Fwd Bytes': 'subflow_fwd_bytes',
    ' Subflow Bwd Packets': 'subflow_bwd_packets',
    ' Subflow Bwd Bytes': 'subflow_bwd_bytes',
    'Init_Win_bytes_forward': 'init_win_fwd',
    ' Init_Win_bytes_backward': 'init_win_bwd',
    ' act_data_pkt_fwd': 'act_data_pkt_fwd',
    ' min_seg_size_forward': 'min_seg_size_forward',
    'Active Mean': 'active_time_mean',
    ' Active Std': 'active_time_std',
    ' Active Max': 'active_time_max',
    ' Active Min': 'active_time_min',
    'Idle Mean': 'idle_time_mean',
    ' Idle Std': 'idle_time_std',
    ' Idle Max': 'idle_time_max',
    ' Idle Min': 'idle_time_min',
    ' Label': 'label'
}

def ingest_dataset(raw_csv_path, force=False):
    if not os.path.exists(raw_csv_path):
        print(f"[!] Error: Raw predefined dataset '{raw_csv_path}' not found.")
        return

    output_path = os.path.join('data', 'training_data.csv')
    if os.path.exists(output_path) and not force:
        confirm = input(f"[?] This will overwrite the current training dataset. Proceed? (y/N): ")
        if confirm.lower() != 'y':
            print("[*] Aborted.")
            return

    print(f"[*] Loading predefined raw dataset from {raw_csv_path}...")
    try:
        df = pd.read_csv(raw_csv_path)
    except Exception as e:
        print(f"[!] Failed to read CSV: {e}")
        return

    print(f"[*] Mapping predefined raw column names to Obsidian Lens backend architecture...")
    
    # Strip whitespace from raw columns just in case
    df.columns = [col.strip() for col in df.columns]
    
    # Map matching columns
    final_cols = {}
    for raw_col, mapped_col in CIC_IDS2017_MAPPING.items():
        clean_raw = raw_col.strip()
        if clean_raw in df.columns:
            final_cols[clean_raw] = mapped_col
        else:
            print(f"  [~] Warning: Missing expected CIC parameter '{clean_raw}' in predefined dataset.")
            # Create dummy zero columns if missing to satisfy 78-params
            df[clean_raw] = 0
            final_cols[clean_raw] = mapped_col

    df.rename(columns=final_cols, inplace=True)

    # Some basic filtering
    df.replace([float('inf'), -float('inf')], 0, inplace=True)
    df.fillna(0, inplace=True)
    
    # Map CIC-IDS labels to Obsidian Lens default profiles
    print(f"[*] Normalizing threat profiles...")
    if 'threat_profile' in df.columns:
        df['threat_profile'] = df['threat_profile'].replace({
            'BENIGN': 'normal_traffic',
            'DDoS': 'ddos_bot'
        })

    # Save to the active backend location
    os.makedirs('data', exist_ok=True)
    df.to_csv(output_path, index=False)
    
    print(f"[SUCCESS] Dataset mapped and ingested! Saved {len(df)} rows to {output_path}.")
    print("[*] Please restart the Obsidian Lens backend (`python app.py`) to hot-load the real data and re-train the Random Forest Model.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ingest predefined CIC-IDS2017 datasets into Obsidian Lens.")
    parser.add_argument("csv_path", help="Path to the raw predefined dataset CSV.")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing dataset.")
    args = parser.parse_args()

    ingest_dataset(args.csv_path, force=args.force)
