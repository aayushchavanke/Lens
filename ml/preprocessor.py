"""
BENFET ML - Data Preprocessor (v2)
Normalizes the 78-feature behavioral vectors using StandardScaler.
Handles missing/infinite values and encodes categorical fields.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import pickle
import os
from config import MODELS_FOLDER, DEFAULT_SCALER_NAME


# Feature columns used for ML — must match feature_extractor.FEATURE_COLUMNS
# These are PURELY behavioral: no IP addresses, no port numbers.
# 78 features across 5 categories.
FEATURE_COLUMNS = [
    # 1. Temporal (21)
    'flow_duration',
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',
    'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_min', 'fwd_iat_max',
    'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_min', 'bwd_iat_max',
    'active_time_mean', 'active_time_std', 'active_time_min', 'active_time_max',
    'idle_time_mean', 'idle_time_std', 'idle_time_min', 'idle_time_max',

    # 2. Spatial (24)
    'total_fwd_packets', 'total_bwd_packets',
    'total_fwd_bytes', 'total_bwd_bytes',
    'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'fwd_pkt_len_min', 'fwd_pkt_len_max',
    'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'bwd_pkt_len_min', 'bwd_pkt_len_max',
    'avg_packet_size', 'pkt_len_variance',
    'spl_1', 'spl_2', 'spl_3', 'spl_4', 'spl_5',
    'spl_6', 'spl_7', 'spl_8', 'spl_9', 'spl_10',

    # 3. Volumetric & Directional (8)
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'down_up_ratio', 'fwd_bwd_packet_ratio',
    'burst_count', 'burst_avg_size', 'burst_avg_duration', 'burst_total_packets',

    # 4. TCP/IP & Flags (14)
    'init_win_fwd', 'init_win_bwd',
    'fwd_header_len', 'bwd_header_len',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
    'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
    'ttl_mean', 'ttl_std',
    'dns_query_count', 'total_packets',

    # 5. Encrypted / TLS (11)
    'tls_num_ciphersuites', 'tls_num_extensions',
    'tls_handshake_duration', 'tls_version', 'tls_has_sni',
    'tls_ext_lengths_mean', 'tls_ext_lengths_std',
    'tls_cipher_entropy', 'tls_is_resumed', 'tls_has_ja3',
    'tls_ja3_numeric',
]

assert len(FEATURE_COLUMNS) == 78, (
    f"FEATURE_COLUMNS length mismatch: expected 78, got {len(FEATURE_COLUMNS)}. "
    "Ensure feature_extractor.py and preprocessor.py are in sync."
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
