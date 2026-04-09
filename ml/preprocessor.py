"""
BENFET ML - Data Preprocessor (v3 — Real Dataset Aligned)
Normalizes behavioral feature vectors using StandardScaler.
Handles missing/infinite values and encodes categorical fields.

FEATURE SET: 48 features — trimmed from 78 to match CICIDS2017 real dataset.
Removed 30 permanently-zeroed features (TLS, SPL, Burst, TTL, DNS) that existed
only in the synthetic generator but have NO real values in CICIDS2017.
Zeroed features in training data provide zero information gain and add noise.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import pickle
import os
from config import MODELS_FOLDER, DEFAULT_SCALER_NAME


# Feature columns used for ML.
# 48 features — all present with real values in CICIDS2017.
# Source: CICIDS2017 column mapping in ml/real_dataset_loader.py
FEATURE_COLUMNS = [
    # 1. Temporal — Flow Duration (1)
    'flow_duration',

    # 2. Temporal — Overall IAT (4)
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',

    # 3. Temporal — Forward IAT (4)
    'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_min', 'fwd_iat_max',

    # 4. Temporal — Backward IAT (4)
    'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_min', 'bwd_iat_max',

    # 5. Temporal — Active / Idle Times (8)
    'active_time_mean', 'active_time_std', 'active_time_min', 'active_time_max',
    'idle_time_mean',   'idle_time_std',   'idle_time_min',   'idle_time_max',

    # 6. Spatial — Directional packet/byte counts (4)
    'total_fwd_packets', 'total_bwd_packets',
    'total_fwd_bytes',   'total_bwd_bytes',

    # 7. Spatial — Forward packet length stats (4)
    'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'fwd_pkt_len_min', 'fwd_pkt_len_max',

    # 8. Spatial — Backward packet length stats (4)
    'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'bwd_pkt_len_min', 'bwd_pkt_len_max',

    # 9. Spatial — Overall packet size statistics (2)
    'avg_packet_size', 'pkt_len_variance',

    # 10. Volumetric — Transfer rates & ratios (4)
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'down_up_ratio',      'fwd_bwd_packet_ratio',

    # 11. TCP/IP — Window sizes (2)
    'init_win_fwd', 'init_win_bwd',

    # 12. TCP/IP — Header lengths (2)
    'fwd_header_len', 'bwd_header_len',

    # 13. TCP/IP — All 6 flag counts (6)
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
    'psh_flag_count', 'ack_flag_count', 'urg_flag_count',

    # REMOVED from previous 78-feature set (all were zero in CICIDS2017):
    # - 10 SPL features (spl_1 through spl_10) — no equivalent in CICIDS
    # - 4 Burst features (burst_count, burst_avg_size, burst_avg_duration, burst_total_packets)
    # - 11 TLS features (tls_num_ciphersuites, tls_cipher_entropy, tls_ja3_numeric, etc.)
    # - ttl_mean, ttl_std, dns_query_count, total_packets, fwd_bwd... — not in CICIDS
]

assert len(FEATURE_COLUMNS) == 49, (
    f"FEATURE_COLUMNS length mismatch: expected 49, got {len(FEATURE_COLUMNS)}. "
    "Ensure real_dataset_loader.py mapping is in sync with this list."
)



class Preprocessor:
    """Preprocesses behavioral feature vectors for ML inference."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit_transform(self, df):
        """
        Fit the scaler on the dataset and return transformed features + labels.

        Args:
            df: DataFrame with feature columns and a 'label' column.

        Returns:
            X: numpy array of scaled features
            y: numpy array of labels
        """
        df = self._clean(df)
        y = df['label'].values if 'label' in df.columns else None

        X = df[FEATURE_COLUMNS].values
        X = self.scaler.fit_transform(X)
        self.is_fitted = True

        return X, y

    def transform(self, df):
        """
        Transform features using a previously fitted scaler.

        Args:
            df: DataFrame with feature columns.

        Returns:
            X: numpy array of scaled features
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor not fitted. Call fit_transform() first or load a saved scaler.")

        df = self._clean(df)
        X = df[FEATURE_COLUMNS].values
        return self.scaler.transform(X)

    def _clean(self, df):
        """Handle missing and infinite values."""
        df = df.copy()

        # Ensure all feature columns exist
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0

        # Replace inf with NaN, then fill NaN with 0
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0)

        return df

    def save(self, path=None):
        """Save the fitted scaler to disk."""
        if path is None:
            path = os.path.join(MODELS_FOLDER, DEFAULT_SCALER_NAME)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(self.scaler, f)

    def load(self, path=None):
        """Load a saved scaler from disk."""
        if path is None:
            path = os.path.join(MODELS_FOLDER, DEFAULT_SCALER_NAME)
        with open(path, 'rb') as f:
            self.scaler = pickle.load(f)
        self.is_fitted = True
