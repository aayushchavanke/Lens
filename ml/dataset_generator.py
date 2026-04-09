"""
BENFET ML - Synthetic Dataset Generator (v2)
Generates realistic behavioral traffic datasets simulating distinct user profiles.
Each profile is defined by characteristic ranges for ALL 77 ML features across
5 categories: Temporal, Spatial, Volumetric, TCP/IP Flags, and TLS/Encrypted.

IMPORTANT: No IP-based labels — profiles represent behavioral fingerprints.
The same profile should match a device regardless of its current IP address.
"""

import numpy as np
import pandas as pd
import math


# ═══════════════════════════════════════════════════════════════════════════════
#  USER BEHAVIORAL PROFILES
#  Each profile defines plausible ranges for behavioral features.
#  The classifier learns these patterns, NOT IP addresses.
# ═══════════════════════════════════════════════════════════════════════════════

USER_PROFILES = {

    'web_browser': {
        # Temporal
        'iat_mean': (0.01, 0.5), 'iat_std': (0.005, 0.2),
        'fwd_iat_ratio': (0.5, 1.5),  # Ratio vs overall IAT
        'bwd_iat_ratio': (0.8, 2.0),
        'active_ratio': (0.3, 0.7), 'idle_ratio': (1.0, 5.0),
        # Spatial
        'fwd_pkt_len_mean': (100, 500), 'fwd_pkt_len_std': (30, 150),
        'bwd_pkt_len_mean': (300, 1200), 'bwd_pkt_len_std': (100, 400),
        'fwd_bwd_pkt_ratio': (0.6, 1.5),
        'spl_base': (100, 600),
        # Volumetric
        'down_up_ratio': (2.0, 8.0), 'packets_per_second': (10, 80),
        'burst_count': (2, 8), 'burst_avg_size': (5, 15),
        # TCP/IP
        'init_win_fwd': (8192, 65535), 'init_win_bwd': (14600, 65535),
        'ttl_mean': (50, 64),
        'syn_ratio': (0.01, 0.05), 'fin_ratio': (0.005, 0.02),
        'psh_ratio': (0.1, 0.4), 'ack_ratio': (0.3, 0.8),
        'dns_query_ratio': (0.05, 0.15),
        # TLS
        'tls_prob': 0.7,
        'tls_ciphersuites': (10, 30), 'tls_extensions': (5, 15),
        'tls_handshake_ms': (20, 200), 'tls_version': (4, 5),
    },

    'video_streamer': {
        'iat_mean': (0.001, 0.02), 'iat_std': (0.0005, 0.01),
        'fwd_iat_ratio': (0.3, 0.8), 'bwd_iat_ratio': (0.5, 1.0),
        'active_ratio': (0.7, 0.95), 'idle_ratio': (0.1, 1.0),
        'fwd_pkt_len_mean': (50, 200), 'fwd_pkt_len_std': (10, 50),
        'bwd_pkt_len_mean': (1000, 1450), 'bwd_pkt_len_std': (100, 300),
        'fwd_bwd_pkt_ratio': (0.1, 0.5),
        'spl_base': (200, 1400),
        'down_up_ratio': (5.0, 20.0), 'packets_per_second': (100, 500),
        'burst_count': (5, 20), 'burst_avg_size': (20, 100),
        'init_win_fwd': (16384, 65535), 'init_win_bwd': (28960, 65535),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.001, 0.005), 'fin_ratio': (0.001, 0.003),
        'psh_ratio': (0.05, 0.2), 'ack_ratio': (0.4, 0.9),
        'dns_query_ratio': (0.001, 0.01),
        'tls_prob': 0.9,
        'tls_ciphersuites': (15, 25), 'tls_extensions': (8, 18),
        'tls_handshake_ms': (30, 150), 'tls_version': (4, 5),
    },

    'ssh_user': {
        'iat_mean': (0.05, 2.0), 'iat_std': (0.02, 1.0),
        'fwd_iat_ratio': (0.8, 1.5), 'bwd_iat_ratio': (0.3, 0.8),
        'active_ratio': (0.1, 0.4), 'idle_ratio': (2.0, 20.0),
        'fwd_pkt_len_mean': (40, 200), 'fwd_pkt_len_std': (10, 60),
        'bwd_pkt_len_mean': (40, 300), 'bwd_pkt_len_std': (15, 80),
        'fwd_bwd_pkt_ratio': (0.6, 1.5),
        'spl_base': (40, 200),
        'down_up_ratio': (0.5, 2.0), 'packets_per_second': (1, 20),
        'burst_count': (0, 3), 'burst_avg_size': (3, 8),
        'init_win_fwd': (8192, 32768), 'init_win_bwd': (8192, 32768),
        'ttl_mean': (60, 64),
        'syn_ratio': (0.02, 0.08), 'fin_ratio': (0.01, 0.05),
        'psh_ratio': (0.2, 0.6), 'ack_ratio': (0.5, 0.9),
        'dns_query_ratio': (0.0, 0.01),
        'tls_prob': 0.0,  # SSH, not TLS
        'tls_ciphersuites': (0, 0), 'tls_extensions': (0, 0),
        'tls_handshake_ms': (0, 0), 'tls_version': (0, 0),
    },

    'file_transfer': {
        'iat_mean': (0.0001, 0.005), 'iat_std': (0.00005, 0.002),
        'fwd_iat_ratio': (0.5, 1.5), 'bwd_iat_ratio': (0.2, 0.6),
        'active_ratio': (0.8, 0.99), 'idle_ratio': (0.01, 0.5),
        'fwd_pkt_len_mean': (1000, 1460), 'fwd_pkt_len_std': (50, 200),
        'bwd_pkt_len_mean': (40, 100), 'bwd_pkt_len_std': (5, 20),
        'fwd_bwd_pkt_ratio': (1.5, 5.0),
        'spl_base': (500, 1460),
        'down_up_ratio': (0.02, 0.2), 'packets_per_second': (200, 1000),
        'burst_count': (10, 50), 'burst_avg_size': (50, 200),
        'init_win_fwd': (32768, 65535), 'init_win_bwd': (16384, 65535),
        'ttl_mean': (58, 64),
        'syn_ratio': (0.001, 0.005), 'fin_ratio': (0.001, 0.003),
        'psh_ratio': (0.05, 0.15), 'ack_ratio': (0.4, 0.9),
        'dns_query_ratio': (0.0, 0.005),
        'tls_prob': 0.3,
        'tls_ciphersuites': (5, 15), 'tls_extensions': (3, 10),
        'tls_handshake_ms': (10, 100), 'tls_version': (3, 5),
    },

    'voip_user': {
        'iat_mean': (0.02, 0.04), 'iat_std': (0.001, 0.01),
        'fwd_iat_ratio': (0.9, 1.1), 'bwd_iat_ratio': (0.9, 1.1),
        'active_ratio': (0.85, 0.98), 'idle_ratio': (0.05, 0.5),
        'fwd_pkt_len_mean': (100, 250), 'fwd_pkt_len_std': (5, 30),
        'bwd_pkt_len_mean': (100, 250), 'bwd_pkt_len_std': (5, 30),
        'fwd_bwd_pkt_ratio': (0.8, 1.2),
        'spl_base': (100, 250),
        'down_up_ratio': (0.8, 1.2), 'packets_per_second': (30, 60),
        'burst_count': (1, 5), 'burst_avg_size': (10, 30),
        'init_win_fwd': (4096, 16384), 'init_win_bwd': (4096, 16384),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.005, 0.02), 'fin_ratio': (0.005, 0.01),
        'psh_ratio': (0.01, 0.05), 'ack_ratio': (0.1, 0.3),
        'dns_query_ratio': (0.005, 0.02),
        'tls_prob': 0.4,
        'tls_ciphersuites': (5, 12), 'tls_extensions': (3, 8),
        'tls_handshake_ms': (15, 80), 'tls_version': (3, 5),
    },

    'malware_c2': {
        'iat_mean': (5.0, 60.0), 'iat_std': (2.0, 30.0),
        'fwd_iat_ratio': (0.8, 1.5), 'bwd_iat_ratio': (0.5, 1.0),
        'active_ratio': (0.01, 0.1), 'idle_ratio': (10.0, 120.0),
        'fwd_pkt_len_mean': (50, 300), 'fwd_pkt_len_std': (20, 80),
        'bwd_pkt_len_mean': (50, 500), 'bwd_pkt_len_std': (20, 150),
        'fwd_bwd_pkt_ratio': (0.5, 2.0),
        'spl_base': (50, 300),
        'down_up_ratio': (0.3, 3.0), 'packets_per_second': (0.01, 2),
        'burst_count': (1, 3), 'burst_avg_size': (3, 10),
        'init_win_fwd': (1024, 8192), 'init_win_bwd': (1024, 8192),
        'ttl_mean': (100, 128),
        'syn_ratio': (0.05, 0.2), 'fin_ratio': (0.02, 0.1),
        'psh_ratio': (0.1, 0.5), 'ack_ratio': (0.3, 0.7),
        'dns_query_ratio': (0.1, 0.4),
        'tls_prob': 0.6,
        'tls_ciphersuites': (3, 10), 'tls_extensions': (2, 6),
        'tls_handshake_ms': (50, 500), 'tls_version': (2, 4),
    },

    'email_client': {
        'iat_mean': (0.5, 5.0), 'iat_std': (0.2, 2.0),
        'fwd_iat_ratio': (0.6, 1.2), 'bwd_iat_ratio': (0.8, 1.5),
        'active_ratio': (0.1, 0.4), 'idle_ratio': (5.0, 30.0),
        'fwd_pkt_len_mean': (200, 800), 'fwd_pkt_len_std': (50, 200),
        'bwd_pkt_len_mean': (300, 1200), 'bwd_pkt_len_std': (100, 400),
        'fwd_bwd_pkt_ratio': (0.3, 0.8),
        'spl_base': (100, 800),
        'down_up_ratio': (1.5, 5.0), 'packets_per_second': (5, 30),
        'burst_count': (1, 5), 'burst_avg_size': (5, 20),
        'init_win_fwd': (8192, 65535), 'init_win_bwd': (8192, 65535),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.01, 0.04), 'fin_ratio': (0.01, 0.03),
        'psh_ratio': (0.15, 0.4), 'ack_ratio': (0.4, 0.8),
        'dns_query_ratio': (0.02, 0.08),
        'tls_prob': 0.8,
        'tls_ciphersuites': (10, 20), 'tls_extensions': (5, 12),
        'tls_handshake_ms': (20, 150), 'tls_version': (4, 5),
    },

    'gaming': {
        'iat_mean': (0.01, 0.05), 'iat_std': (0.002, 0.02),
        'fwd_iat_ratio': (0.9, 1.1), 'bwd_iat_ratio': (0.9, 1.1),
        'active_ratio': (0.7, 0.95), 'idle_ratio': (0.1, 2.0),
        'fwd_pkt_len_mean': (50, 150), 'fwd_pkt_len_std': (10, 40),
        'bwd_pkt_len_mean': (50, 200), 'bwd_pkt_len_std': (10, 50),
        'fwd_bwd_pkt_ratio': (0.7, 1.3),
        'spl_base': (50, 200),
        'down_up_ratio': (0.8, 1.5), 'packets_per_second': (20, 120),
        'burst_count': (5, 15), 'burst_avg_size': (10, 40),
        'init_win_fwd': (8192, 32768), 'init_win_bwd': (8192, 32768),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.005, 0.02), 'fin_ratio': (0.002, 0.01),
        'psh_ratio': (0.05, 0.2), 'ack_ratio': (0.3, 0.7),
        'dns_query_ratio': (0.005, 0.02),
        'tls_prob': 0.5,
        'tls_ciphersuites': (5, 15), 'tls_extensions': (3, 10),
        'tls_handshake_ms': (15, 100), 'tls_version': (4, 5),
    },

    'cryptominer': {
        'iat_mean': (0.1, 1.0), 'iat_std': (0.05, 0.5),
        'fwd_iat_ratio': (0.9, 1.5), 'bwd_iat_ratio': (0.5, 1.0),
        'active_ratio': (0.5, 0.9), 'idle_ratio': (2.0, 10.0),
        'fwd_pkt_len_mean': (50, 200), 'fwd_pkt_len_std': (10, 50),
        'bwd_pkt_len_mean': (50, 300), 'bwd_pkt_len_std': (10, 80),
        'fwd_bwd_pkt_ratio': (1.0, 3.0),
        'spl_base': (50, 200),
        'down_up_ratio': (0.5, 2.0), 'packets_per_second': (1, 10),
        'burst_count': (1, 5), 'burst_avg_size': (5, 20),
        'init_win_fwd': (4096, 32768), 'init_win_bwd': (4096, 32768),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.01, 0.05), 'fin_ratio': (0.01, 0.05),
        'psh_ratio': (0.1, 0.4), 'ack_ratio': (0.4, 0.8),
        'dns_query_ratio': (0.01, 0.1),
        'tls_prob': 0.8,
        'tls_ciphersuites': (5, 15), 'tls_extensions': (3, 10),
        'tls_handshake_ms': (20, 100), 'tls_version': (3, 5),
    },

    'ddos_bot': {
        'iat_mean': (0.0001, 0.005), 'iat_std': (0.0001, 0.002),
        'fwd_iat_ratio': (1.0, 2.0), 'bwd_iat_ratio': (0.1, 0.5),
        'active_ratio': (0.9, 0.99), 'idle_ratio': (0.0, 0.1),
        'fwd_pkt_len_mean': (40, 100), 'fwd_pkt_len_std': (0, 20),
        'bwd_pkt_len_mean': (40, 60), 'bwd_pkt_len_std': (0, 10),
        'fwd_bwd_pkt_ratio': (5.0, 100.0),
        'spl_base': (40, 100),
        'down_up_ratio': (0.01, 0.1), 'packets_per_second': (500, 5000),
        'burst_count': (20, 100), 'burst_avg_size': (50, 500),
        'init_win_fwd': (1024, 8192), 'init_win_bwd': (1024, 8192),
        'ttl_mean': (100, 128),
        'syn_ratio': (0.5, 0.9), 'fin_ratio': (0.0, 0.01),
        'psh_ratio': (0.0, 0.1), 'ack_ratio': (0.0, 0.1),
        'dns_query_ratio': (0.0, 0.01),
        'tls_prob': 0.0,
        'tls_ciphersuites': (0, 0), 'tls_extensions': (0, 0),
        'tls_handshake_ms': (0, 0), 'tls_version': (0, 0),
    },

    'ransomware_transfer': {
        'iat_mean': (0.001, 0.01), 'iat_std': (0.0005, 0.005),
        'fwd_iat_ratio': (1.0, 3.0), 'bwd_iat_ratio': (0.2, 0.8),
        'active_ratio': (0.9, 0.99), 'idle_ratio': (0.05, 0.2),
        'fwd_pkt_len_mean': (1200, 1460), 'fwd_pkt_len_std': (50, 150),
        'bwd_pkt_len_mean': (40, 100), 'bwd_pkt_len_std': (5, 30),
        'fwd_bwd_pkt_ratio': (2.0, 8.0),
        'spl_base': (1200, 1460),
        'down_up_ratio': (0.02, 0.1), 'packets_per_second': (100, 800),
        'burst_count': (10, 40), 'burst_avg_size': (50, 250),
        'init_win_fwd': (16384, 65535), 'init_win_bwd': (8192, 32768),
        'ttl_mean': (60, 128),
        'syn_ratio': (0.001, 0.005), 'fin_ratio': (0.001, 0.003),
        'psh_ratio': (0.1, 0.3), 'ack_ratio': (0.5, 0.9),
        'dns_query_ratio': (0.0, 0.005),
        'tls_prob': 0.8,
        'tls_ciphersuites': (3, 8), 'tls_extensions': (2, 5),
        'tls_handshake_ms': (50, 150), 'tls_version': (3, 5),
    },

    'brute_force_ssh': {
        'iat_mean': (0.5, 2.0), 'iat_std': (0.1, 0.5),
        'fwd_iat_ratio': (1.0, 1.5), 'bwd_iat_ratio': (0.8, 1.2),
        'active_ratio': (0.2, 0.6), 'idle_ratio': (1.0, 5.0),
        'fwd_pkt_len_mean': (40, 120), 'fwd_pkt_len_std': (10, 30),
        'bwd_pkt_len_mean': (40, 120), 'bwd_pkt_len_std': (10, 30),
        'fwd_bwd_pkt_ratio': (0.8, 1.2),
        'spl_base': (40, 120),
        'down_up_ratio': (0.8, 1.2), 'packets_per_second': (5, 50),
        'burst_count': (5, 20), 'burst_avg_size': (5, 15),
        'init_win_fwd': (4096, 16384), 'init_win_bwd': (4096, 16384),
        'ttl_mean': (60, 64),
        'syn_ratio': (0.05, 0.15), 'fin_ratio': (0.01, 0.05),
        'psh_ratio': (0.2, 0.6), 'ack_ratio': (0.4, 0.8),
        'dns_query_ratio': (0.0, 0.01),
        'tls_prob': 0.0,
        'tls_ciphersuites': (0, 0), 'tls_extensions': (0, 0),
        'tls_handshake_ms': (0, 0), 'tls_version': (0, 0),
    },

    'apt_exfiltration': {
        'iat_mean': (5.0, 300.0), 'iat_std': (1.0, 50.0),
        'fwd_iat_ratio': (1.0, 2.0), 'bwd_iat_ratio': (0.5, 1.0),
        'active_ratio': (0.05, 0.2), 'idle_ratio': (10.0, 50.0),
        'fwd_pkt_len_mean': (500, 1400), 'fwd_pkt_len_std': (100, 300),
        'bwd_pkt_len_mean': (50, 100), 'bwd_pkt_len_std': (10, 20),
        'fwd_bwd_pkt_ratio': (2.0, 20.0),
        'spl_base': (500, 1200),
        'down_up_ratio': (0.05, 0.2), 'packets_per_second': (0.1, 5),
        'burst_count': (2, 5), 'burst_avg_size': (50, 200),
        'init_win_fwd': (8192, 32768), 'init_win_bwd': (8192, 32768),
        'ttl_mean': (100, 128),
        'syn_ratio': (0.005, 0.02), 'fin_ratio': (0.005, 0.02),
        'psh_ratio': (0.1, 0.4), 'ack_ratio': (0.5, 0.9),
        'dns_query_ratio': (0.05, 0.2),
        'tls_prob': 0.9,
        'tls_ciphersuites': (3, 8), 'tls_extensions': (2, 5),
        'tls_handshake_ms': (50, 300), 'tls_version': (4, 5),
    },
    
    'vpn_malware_c2': {
        'iat_mean': (5.0, 60.0), 'iat_std': (2.0, 30.0),
        'fwd_iat_ratio': (0.8, 1.5), 'bwd_iat_ratio': (0.5, 1.0),
        'active_ratio': (0.01, 0.1), 'idle_ratio': (10.0, 120.0),
        'fwd_pkt_len_mean': (200, 500), 'fwd_pkt_len_std': (50, 150),
        'bwd_pkt_len_mean': (300, 800), 'bwd_pkt_len_std': (50, 200),
        'fwd_bwd_pkt_ratio': (0.5, 2.0),
        'spl_base': (200, 500),
        'down_up_ratio': (0.3, 3.0), 'packets_per_second': (0.01, 2),
        'burst_count': (1, 3), 'burst_avg_size': (3, 10),
        'init_win_fwd': (8192, 32768), 'init_win_bwd': (8192, 32768),
        'ttl_mean': (100, 128),
        'syn_ratio': (0.01, 0.05), 'fin_ratio': (0.01, 0.05),
        'psh_ratio': (0.2, 0.6), 'ack_ratio': (0.4, 0.8),
        'dns_query_ratio': (0.01, 0.05),
        'tls_prob': 0.95,
        'tls_ciphersuites': (10, 20), 'tls_extensions': (5, 12),
        'tls_handshake_ms': (100, 500), 'tls_version': (4, 5),
    },

    'vpn_user': {
        'iat_mean': (0.02, 0.2), 'iat_std': (0.01, 0.1),
        'fwd_iat_ratio': (0.8, 1.2), 'bwd_iat_ratio': (0.8, 1.2),
        'active_ratio': (0.6, 0.9), 'idle_ratio': (0.5, 3.0),
        'fwd_pkt_len_mean': (200, 1000), 'fwd_pkt_len_std': (50, 300),
        'bwd_pkt_len_mean': (200, 1000), 'bwd_pkt_len_std': (50, 300),
        'fwd_bwd_pkt_ratio': (0.5, 2.0),
        'spl_base': (200, 1000),
        'down_up_ratio': (0.5, 2.0), 'packets_per_second': (10, 100),
        'burst_count': (5, 20), 'burst_avg_size': (10, 50),
        'init_win_fwd': (8192, 65535), 'init_win_bwd': (8192, 65535),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.005, 0.02), 'fin_ratio': (0.005, 0.02),
        'psh_ratio': (0.1, 0.5), 'ack_ratio': (0.3, 0.7),
        'dns_query_ratio': (0.001, 0.02),
        'tls_prob': 0.95,
        'tls_ciphersuites': (10, 30), 'tls_extensions': (5, 15),
        'tls_handshake_ms': (30, 200), 'tls_version': (4, 5),
    },

    'smart_home_device': {
        'iat_mean': (1.0, 10.0), 'iat_std': (0.5, 5.0),
        'fwd_iat_ratio': (0.9, 1.1), 'bwd_iat_ratio': (0.9, 1.1),
        'active_ratio': (0.05, 0.2), 'idle_ratio': (5.0, 50.0),
        'fwd_pkt_len_mean': (50, 150), 'fwd_pkt_len_std': (10, 30),
        'bwd_pkt_len_mean': (50, 200), 'bwd_pkt_len_std': (10, 40),
        'fwd_bwd_pkt_ratio': (0.8, 1.5),
        'spl_base': (50, 150),
        'down_up_ratio': (0.5, 1.5), 'packets_per_second': (0.1, 5),
        'burst_count': (1, 3), 'burst_avg_size': (2, 10),
        'init_win_fwd': (4096, 16384), 'init_win_bwd': (4096, 16384),
        'ttl_mean': (60, 64),
        'syn_ratio': (0.02, 0.1), 'fin_ratio': (0.02, 0.08),
        'psh_ratio': (0.05, 0.2), 'ack_ratio': (0.2, 0.5),
        'dns_query_ratio': (0.05, 0.15),
        'tls_prob': 0.7,
        'tls_ciphersuites': (3, 10), 'tls_extensions': (2, 8),
        'tls_handshake_ms': (50, 250), 'tls_version': (3, 5),
    },

    'database_sync': {
        'iat_mean': (0.005, 0.05), 'iat_std': (0.001, 0.02),
        'fwd_iat_ratio': (0.8, 1.2), 'bwd_iat_ratio': (0.8, 1.2),
        'active_ratio': (0.9, 0.99), 'idle_ratio': (0.01, 0.2),
        'fwd_pkt_len_mean': (500, 1400), 'fwd_pkt_len_std': (100, 400),
        'bwd_pkt_len_mean': (50, 150), 'bwd_pkt_len_std': (10, 30),
        'fwd_bwd_pkt_ratio': (2.0, 10.0),
        'spl_base': (500, 1400),
        'down_up_ratio': (0.05, 0.5), 'packets_per_second': (50, 500),
        'burst_count': (10, 50), 'burst_avg_size': (20, 100),
        'init_win_fwd': (32768, 65535), 'init_win_bwd': (16384, 65535),
        'ttl_mean': (55, 64),
        'syn_ratio': (0.001, 0.005), 'fin_ratio': (0.001, 0.005),
        'psh_ratio': (0.1, 0.5), 'ack_ratio': (0.5, 0.9),
        'dns_query_ratio': (0.0, 0.005),
        'tls_prob': 0.8,
        'tls_ciphersuites': (5, 15), 'tls_extensions': (3, 10),
        'tls_handshake_ms': (20, 150), 'tls_version': (4, 5),
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  DATASET GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_dataset(n_samples_per_profile=200, profiles=None, random_state=42):
    """
    Generate a synthetic behavioral feature dataset.

    Args:
        n_samples_per_profile: Number of samples per user profile.
        profiles: List of profile names to include (None = all).
        random_state: Random seed for reproducibility.

    Returns:
        pandas DataFrame with 77 feature columns and a 'label' column.
    """
    np.random.seed(random_state)

    if profiles is None:
        profiles = list(USER_PROFILES.keys())

    all_rows = []
    for profile_name in profiles:
        profile = USER_PROFILES[profile_name]
        for _ in range(n_samples_per_profile):
            row = _generate_sample(profile, profile_name)
            all_rows.append(row)

    df = pd.DataFrame(all_rows)
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    return df


def _generate_sample(profile, label):
    """Generate a single sample from a profile's parameter ranges."""

    def _rand(key, default=(0, 0)):
        val = profile.get(key, default)
        if isinstance(val, tuple):
            return np.random.uniform(val[0], val[1])
        return val

    # ─── Base parameters ─────────────────────────────────────────────
    iat_mean = _rand('iat_mean')
    iat_std = _rand('iat_std')
    fwd_iat_ratio = _rand('fwd_iat_ratio')
    bwd_iat_ratio = _rand('bwd_iat_ratio')
    active_ratio = _rand('active_ratio')
    idle_ratio = _rand('idle_ratio')

    fwd_pkt_mean = _rand('fwd_pkt_len_mean')
    fwd_pkt_std = _rand('fwd_pkt_len_std')
    bwd_pkt_mean = _rand('bwd_pkt_len_mean')
    bwd_pkt_std = _rand('bwd_pkt_len_std')
    fwd_bwd_ratio = _rand('fwd_bwd_pkt_ratio')

    down_up_ratio = _rand('down_up_ratio')
    pps = _rand('packets_per_second')
    burst_count = int(_rand('burst_count'))
    burst_avg_size = _rand('burst_avg_size')

    ttl_mean = _rand('ttl_mean')
    init_win_fwd = int(_rand('init_win_fwd'))
    init_win_bwd = int(_rand('init_win_bwd'))

    # ─── Derived ─────────────────────────────────────────────────────
    total_packets = int(np.random.uniform(50, 5000))
    flow_duration = total_packets / max(pps, 0.01)

    total_fwd = int(total_packets * fwd_bwd_ratio / (1 + fwd_bwd_ratio))
    total_bwd = total_packets - total_fwd
    total_fwd_bytes = int(total_fwd * fwd_pkt_mean)
    total_bwd_bytes = int(total_bwd * bwd_pkt_mean)

    # SPL (Sequence of first 10 packet lengths)
    spl_base = _rand('spl_base')
    spl = [max(40, int(spl_base + np.random.normal(0, fwd_pkt_std))) for _ in range(10)]

    # Active/idle time
    active_mean = iat_mean * active_ratio
    idle_mean = iat_mean * idle_ratio

    # TLS features
    has_tls = np.random.random() < profile.get('tls_prob', 0)
    tls_cs = int(_rand('tls_ciphersuites')) if has_tls else 0
    tls_ext = int(_rand('tls_extensions')) if has_tls else 0
    tls_hs = _rand('tls_handshake_ms') if has_tls else 0
    tls_ver = int(_rand('tls_version')) if has_tls else 0

    return {
        # ═══ 1. TEMPORAL (20) ════════════════════════════════════════
        'flow_duration': round(flow_duration, 4),
        'iat_mean': round(iat_mean, 6),
        'iat_std': round(iat_std, 6),
        'iat_min': round(max(0, iat_mean - 2 * iat_std), 6),
        'iat_max': round(iat_mean + 3 * iat_std, 6),

        'fwd_iat_mean': round(iat_mean * fwd_iat_ratio, 6),
        'fwd_iat_std': round(iat_std * fwd_iat_ratio, 6),
        'fwd_iat_min': round(max(0, iat_mean * fwd_iat_ratio - 2 * iat_std), 6),
        'fwd_iat_max': round(iat_mean * fwd_iat_ratio + 3 * iat_std, 6),

        'bwd_iat_mean': round(iat_mean * bwd_iat_ratio, 6),
        'bwd_iat_std': round(iat_std * bwd_iat_ratio, 6),
        'bwd_iat_min': round(max(0, iat_mean * bwd_iat_ratio - 2 * iat_std), 6),
        'bwd_iat_max': round(iat_mean * bwd_iat_ratio + 3 * iat_std, 6),

        'active_time_mean': round(active_mean, 6),
        'active_time_std': round(active_mean * np.random.uniform(0.1, 0.5), 6),
        'active_time_min': round(active_mean * np.random.uniform(0.1, 0.5), 6),
        'active_time_max': round(active_mean * np.random.uniform(1.5, 3.0), 6),

        'idle_time_mean': round(idle_mean, 6),
        'idle_time_std': round(idle_mean * np.random.uniform(0.2, 0.8), 6),
        'idle_time_min': round(idle_mean * np.random.uniform(0.1, 0.5), 6),
        'idle_time_max': round(idle_mean * np.random.uniform(1.5, 5.0), 6),

        # ═══ 2. SPATIAL (24) ═════════════════════════════════════════
        'total_fwd_packets': total_fwd,
        'total_bwd_packets': total_bwd,
        'total_fwd_bytes': total_fwd_bytes,
        'total_bwd_bytes': total_bwd_bytes,

        'fwd_pkt_len_mean': round(fwd_pkt_mean, 2),
        'fwd_pkt_len_std': round(fwd_pkt_std, 2),
        'fwd_pkt_len_min': max(40, int(fwd_pkt_mean - 3 * fwd_pkt_std)),
        'fwd_pkt_len_max': int(fwd_pkt_mean + 3 * fwd_pkt_std),

        'bwd_pkt_len_mean': round(bwd_pkt_mean, 2),
        'bwd_pkt_len_std': round(bwd_pkt_std, 2),
        'bwd_pkt_len_min': max(40, int(bwd_pkt_mean - 3 * bwd_pkt_std)),
        'bwd_pkt_len_max': int(bwd_pkt_mean + 3 * bwd_pkt_std),

        'avg_packet_size': round((fwd_pkt_mean + bwd_pkt_mean) / 2, 2),
        'pkt_len_variance': round(((fwd_pkt_std + bwd_pkt_std) / 2) ** 2, 2),

        'spl_1': spl[0], 'spl_2': spl[1], 'spl_3': spl[2], 'spl_4': spl[3],
        'spl_5': spl[4], 'spl_6': spl[5], 'spl_7': spl[6], 'spl_8': spl[7],
        'spl_9': spl[8], 'spl_10': spl[9],

        # ═══ 3. VOLUMETRIC & DIRECTIONAL (8) ═════════════════════════
        'flow_bytes_per_sec': round((total_fwd_bytes + total_bwd_bytes) / max(flow_duration, 0.0001), 2),
        'flow_packets_per_sec': round(pps, 2),
        'down_up_ratio': round(down_up_ratio, 4),
        'fwd_bwd_packet_ratio': round(fwd_bwd_ratio, 4),
        'burst_count': burst_count,
        'burst_avg_size': round(burst_avg_size, 2),
        'burst_avg_duration': round(burst_avg_size * iat_mean, 6),
        'burst_total_packets': int(burst_count * burst_avg_size),

        # ═══ 4. TCP/IP & FLAGS (14) ══════════════════════════════════
        'init_win_fwd': init_win_fwd,
        'init_win_bwd': init_win_bwd,
        'fwd_header_len': int(total_fwd * np.random.uniform(20, 60)),
        'bwd_header_len': int(total_bwd * np.random.uniform(20, 60)),

        'fin_flag_count': int(total_packets * _rand('fin_ratio', (0.005, 0.02))),
        'syn_flag_count': int(total_packets * _rand('syn_ratio', (0.01, 0.05))),
        'rst_flag_count': int(np.random.poisson(0.5)),
        'psh_flag_count': int(total_packets * _rand('psh_ratio', (0.05, 0.3))),
        'ack_flag_count': int(total_packets * _rand('ack_ratio', (0.3, 0.8))),
        'urg_flag_count': int(np.random.poisson(0.1)),

        'ttl_mean': round(ttl_mean, 2),
        'ttl_std': round(np.random.uniform(0, 5), 2),
        'dns_query_count': int(total_packets * _rand('dns_query_ratio', (0.01, 0.05))),
        'total_packets': total_packets,

        # ═══ 5. TLS / ENCRYPTED (11) ═════════════════════════════════
        'tls_num_ciphersuites': tls_cs,
        'tls_num_extensions': tls_ext,
        'tls_handshake_duration': round(tls_hs, 3),
        'tls_version': tls_ver,
        'tls_has_sni': 1 if has_tls and np.random.random() > 0.2 else 0,
        'tls_ext_lengths_mean': round(np.random.uniform(5, 50), 2) if has_tls else 0,
        'tls_ext_lengths_std': round(np.random.uniform(2, 20), 2) if has_tls else 0,
        'tls_cipher_entropy': round(np.random.uniform(3, 5), 4) if has_tls else 0,
        'tls_is_resumed': 1 if has_tls and np.random.random() > 0.7 else 0,
        'tls_has_ja3': 1 if has_tls else 0,
        'tls_ja3_numeric': round(np.random.uniform(0, 1), 6) if has_tls else 0,

        # ═══ LABEL (behavioral class — NOT an IP address) ════════════
        'label': label,
    }
