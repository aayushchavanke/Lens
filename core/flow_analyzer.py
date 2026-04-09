"""
BENFET Core - Flow Analyzer
Extended flow-level analysis: DNS patterns, TLS metadata,
connection frequency, and time-windowed statistics.
"""

import numpy as np
from collections import defaultdict


def analyze_flows(parsed_data):
    """
    Perform extended flow analysis on parsed PCAP data.

    Args:
        parsed_data: Output from pcap_parser.parse_pcap()

    Returns:
        dict with:
            - 'flow_summaries': per-flow summary dicts
            - 'dns_analysis': DNS query pattern analysis
            - 'connection_frequency': connection frequency per endpoint
            - 'time_series': time-windowed aggregate statistics
            - 'protocol_distribution': protocol usage breakdown
    """
    packets = parsed_data['packets']
    flows = parsed_data['raw_flows']

    flow_summaries = _build_flow_summaries(flows)
    dns_analysis = _analyze_dns_patterns(packets)
    conn_freq = _connection_frequency(packets)
    time_series = _time_windowed_stats(packets, window_seconds=60)
    proto_dist = _protocol_distribution(packets)

    return {
        'flow_summaries': flow_summaries,
        'dns_analysis': dns_analysis,
        'connection_frequency': conn_freq,
        'time_series': time_series,
        'protocol_distribution': proto_dist,
    }


def _build_flow_summaries(flows):
    """Build concise summaries for each flow."""
    summaries = []
    for key, packets in flows.items():
        if not packets:
            continue

        timestamps = sorted([p['timestamp'] for p in packets])
        sizes = [p['packet_length'] for p in packets]
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

        summaries.append({
            'flow': f"{key[0]}:{key[2]} <-> {key[1]}:{key[3]}",
            'protocol': packets[0].get('protocol_name', 'UNKNOWN'),
            'total_packets': len(packets),
            'total_bytes': sum(sizes),
            'duration': round(duration, 4),
            'avg_packet_size': round(np.mean(sizes), 2),
            'start_time': timestamps[0],
            'end_time': timestamps[-1],
        })

    return sorted(summaries, key=lambda x: x['total_bytes'], reverse=True)


def _analyze_dns_patterns(packets):
    """Analyze DNS query patterns and frequency."""
    dns_packets = [p for p in packets if p.get('has_dns', False)]
    dns_sources = defaultdict(int)

    for pkt in dns_packets:
        dns_sources[pkt['src_ip']] += 1

    return {
        'total_dns_queries': len(dns_packets),
        'dns_sources': dict(dns_sources),
        'dns_ratio': len(dns_packets) / max(len(packets), 1),
    }


def _connection_frequency(packets):
    """Count unique connections per source IP over time."""
    connections = defaultdict(set)

    for pkt in packets:
        src = pkt['src_ip']
        dst = pkt['dst_ip']
        dst_port = pkt['dst_port']
        connections[src].add((dst, dst_port))

    result = {}
    for ip, conns in connections.items():
        result[ip] = {
            'unique_destinations': len(conns),
            'destinations': [{'ip': c[0], 'port': c[1]} for c in list(conns)[:20]],
        }

    return result


def _time_windowed_stats(packets, window_seconds=60):
    """Compute aggregate statistics over time windows."""
    if not packets:
        return []

    timestamps = [p['timestamp'] for p in packets]
    start_time = min(timestamps)
    end_time = max(timestamps)

    windows = []
    current = start_time

    while current < end_time:
        window_end = current + window_seconds
        window_pkts = [p for p in packets if current <= p['timestamp'] < window_end]

        if window_pkts:
            sizes = [p['packet_length'] for p in window_pkts]
            windows.append({
                'window_start': current,
                'window_end': window_end,
                'packet_count': len(window_pkts),
                'total_bytes': sum(sizes),
                'avg_packet_size': round(np.mean(sizes), 2),
                'unique_src_ips': len(set(p['src_ip'] for p in window_pkts)),
                'unique_dst_ips': len(set(p['dst_ip'] for p in window_pkts)),
            })
        else:
            windows.append({
                'window_start': current,
                'window_end': window_end,
                'packet_count': 0,
                'total_bytes': 0,
                'avg_packet_size': 0,
                'unique_src_ips': 0,
                'unique_dst_ips': 0,
            })

        current = window_end

    return windows


def _protocol_distribution(packets):
    """Compute protocol usage distribution."""
    proto_counts = defaultdict(int)
    proto_bytes = defaultdict(int)

    for pkt in packets:
        proto = pkt.get('protocol_name', 'UNKNOWN')
        proto_counts[proto] += 1
        proto_bytes[proto] += pkt['packet_length']

    total_pkts = max(len(packets), 1)
    total_bytes = max(sum(p['packet_length'] for p in packets), 1)

    distribution = []
    for proto in proto_counts:
        distribution.append({
            'protocol': proto,
            'packet_count': proto_counts[proto],
            'byte_count': proto_bytes[proto],
            'packet_ratio': round(proto_counts[proto] / total_pkts, 4),
            'byte_ratio': round(proto_bytes[proto] / total_bytes, 4),
        })

    return sorted(distribution, key=lambda x: x['byte_count'], reverse=True)
