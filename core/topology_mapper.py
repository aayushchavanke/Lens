"""
BENFET Core - Network Topology Mapper
Maps IP/MAC relationships into a network graph for visualization.
Identifies subnets, hub nodes, and communication matrices.
"""

from collections import defaultdict
import math


def build_topology(parsed_data):
    """
    Build a network topology graph from parsed PCAP data.

    Args:
        parsed_data: Output from pcap_parser.parse_pcap()

    Returns:
        dict with:
            - 'nodes': list of node dicts (id, label, type, degree, mac, subnet)
            - 'links': list of link dicts (source, target, weight, protocols)
            - 'subnets': dict grouping IPs by /24 subnet
            - 'comm_matrix': 2D communication matrix (bytes exchanged)
            - 'stats': summary statistics
    """
    packets = parsed_data['packets']
    nodes = {}
    links = defaultdict(lambda: {'weight': 0, 'packets': 0, 'protocols': set(), 'bytes': 0})
    ip_mac_map = defaultdict(set)

    for pkt in packets:
        src = pkt['src_ip']
        dst = pkt['dst_ip']

        # Track nodes
        if src not in nodes:
            nodes[src] = {'id': src, 'label': src, 'mac': set(), 'total_bytes': 0, 'total_packets': 0}
        if dst not in nodes:
            nodes[dst] = {'id': dst, 'label': dst, 'mac': set(), 'total_bytes': 0, 'total_packets': 0}

        nodes[src]['total_bytes'] += pkt['packet_length']
        nodes[src]['total_packets'] += 1
        nodes[dst]['total_bytes'] += pkt['packet_length']
        nodes[dst]['total_packets'] += 1

        # MAC tracking
        if pkt.get('src_mac'):
            nodes[src]['mac'].add(pkt['src_mac'])
            ip_mac_map[src].add(pkt['src_mac'])
        if pkt.get('dst_mac'):
            nodes[dst]['mac'].add(pkt['dst_mac'])
            ip_mac_map[dst].add(pkt['dst_mac'])

        # Track links (bidirectional)
        link_key = tuple(sorted([src, dst]))
        links[link_key]['weight'] += pkt['packet_length']
        links[link_key]['packets'] += 1
        links[link_key]['bytes'] += pkt['packet_length']
        links[link_key]['protocols'].add(pkt.get('protocol_name', 'UNKNOWN'))

    # Compute degree centrality
    degree_count = defaultdict(int)
    for (a, b) in links:
        degree_count[a] += 1
        degree_count[b] += 1

    max_degree = max(degree_count.values()) if degree_count else 1

    # Build node list
    node_list = []
    for ip, data in nodes.items():
        degree = degree_count.get(ip, 0)
        node_list.append({
            'id': ip,
            'label': ip,
            'mac': list(data['mac']),
            'total_bytes': data['total_bytes'],
            'total_packets': data['total_packets'],
            'degree': degree,
            'degree_centrality': degree / max_degree if max_degree > 0 else 0,
            'subnet': _get_subnet(ip),
            'is_hub': degree > (max_degree * 0.6),
            'size': max(8, min(40, 8 + degree * 4)),
        })

    # Build link list
    link_list = []
    for (src, dst), data in links.items():
        link_list.append({
            'source': src,
            'target': dst,
            'weight': data['weight'],
            'packets': data['packets'],
            'bytes': data['bytes'],
            'protocols': list(data['protocols']),
            'thickness': max(1, min(8, math.log2(max(data['packets'], 1)) + 1)),
        })

    # Subnet grouping
    subnets = defaultdict(list)
    for node in node_list:
        subnets[node['subnet']].append(node['id'])

    # Communication matrix
    all_ips = sorted(nodes.keys())
    comm_matrix = {ip: {ip2: 0 for ip2 in all_ips} for ip in all_ips}
    for (src, dst), data in links.items():
        comm_matrix[src][dst] = data['bytes']
        comm_matrix[dst][src] = data['bytes']

    stats = {
        'total_nodes': len(node_list),
        'total_links': len(link_list),
        'total_subnets': len(subnets),
        'hub_nodes': [n['id'] for n in node_list if n['is_hub']],
    }

    return {
        'nodes': node_list,
        'links': link_list,
        'subnets': dict(subnets),
        'comm_matrix': comm_matrix,
        'stats': stats,
    }


def _get_subnet(ip):
    """Extract /24 subnet from an IP address."""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return 'unknown'
