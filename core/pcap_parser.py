"""
BENFET Core - PCAP Parser (v2)
Parses PCAP/PCAPNG files using Scapy and extracts comprehensive per-packet metadata.
Groups packets into bidirectional flows with directional tracking.
Extracts TCP window sizes, header lengths, and TLS/SSL handshake metadata.
"""

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether, DNS, Raw
    SCAPY_AVAILABLE = True
except Exception as exc:
    SCAPY_AVAILABLE = False
    rdpcap = None
    IP = TCP = UDP = ICMP = Ether = DNS = Raw = None

from collections import defaultdict
import hashlib
import struct


# ─── TLS Constants ──────────────────────────────────────────────────────────

TLS_CONTENT_TYPE_HANDSHAKE = 22
TLS_HANDSHAKE_CLIENT_HELLO = 1
TLS_HANDSHAKE_SERVER_HELLO = 2

TLS_VERSIONS = {
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
    0x0304: 'TLS 1.3',
    0x0300: 'SSL 3.0',
}


# ─── Flow Key ───────────────────────────────────────────────────────────────

def _flow_key(pkt):
    """Generate a bidirectional flow key from a packet.
    Returns (initiator_ip, responder_ip, initiator_port, responder_port, proto)
    The first packet's source is treated as the initiator (forward direction).
    """
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto = ip.proto
    src_ip = ip.src
    dst_ip = ip.dst
    src_port = 0
    dst_port = 0

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    # Bidirectional: sort so both directions map to the same key
    # Explicitly cast ports to int to ensure consistent str() representation
    src_port = int(src_port)
    dst_port = int(dst_port)
    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, src_ip, dst_port, src_port, proto)
    return (src_ip, dst_ip, src_port, dst_port, proto)


# ─── Main Parser ────────────────────────────────────────────────────────────

def parse_pcap(filepath):
    """
    Parse a PCAP file and return structured packet data with comprehensive metadata.

    Returns:
        dict with keys:
            - 'packets': list of packet dicts with extended metadata
            - 'flows': dict mapping flow_key_str -> list of packet dicts
            - 'raw_flows': dict mapping flow_key_tuple -> list of packet dicts
            - 'metadata': dict with file-level info
            - 'tls_flows': dict of TLS handshake data per flow
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy library is required for PCAP parsing. Install via 'pip install scapy'.")

    packets = rdpcap(filepath)
    parsed_packets = []
    flows = defaultdict(list)
    flow_initiators = {}  # Track who initiated each flow (first packet src)
    tls_flows = defaultdict(lambda: {
        'client_hello': None, 'server_hello': None,
        'ciphersuites': [], 'extensions': [],
        'ja3': None, 'ja3s': None,
        'handshake_start': None, 'handshake_end': None,
    })

    for pkt in packets:
        pkt_data = _extract_packet_data(pkt)
        if pkt_data is None:
            continue

        fk = _flow_key(pkt)
        if fk:
            # Track flow initiator (first packet defines forward direction)
            if fk not in flow_initiators:
                flow_initiators[fk] = pkt_data['src_ip']

            # Mark direction: forward = same as initiator, backward = opposite
            pkt_data['is_forward'] = (pkt_data['src_ip'] == flow_initiators[fk])
            flows[fk].append(pkt_data)

            # TLS extraction
            _extract_tls_metadata(pkt, fk, pkt_data, tls_flows)
        else:
            pkt_data['is_forward'] = True

        parsed_packets.append(pkt_data)

    # Compute TLS handshake durations and JA3 hashes
    for fk, tls_data in tls_flows.items():
        if tls_data['handshake_start'] and tls_data['handshake_end']:
            tls_data['handshake_duration_ms'] = round(
                (tls_data['handshake_end'] - tls_data['handshake_start']) * 1000, 3
            )
        else:
            tls_data['handshake_duration_ms'] = 0

    # File-level metadata
    timestamps = [p['timestamp'] for p in parsed_packets]
    metadata = {
        'total_packets': len(parsed_packets),
        'total_flows': len(flows),
        'capture_duration': max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0,
        'start_time': min(timestamps) if timestamps else 0,
        'end_time': max(timestamps) if timestamps else 0,
        'file': filepath,
        'tls_flows_detected': sum(1 for t in tls_flows.values() if t['client_hello']),
    }

    # Convert flow keys to string for JSON serialization
    str_flows = {}
    for key, pkts in flows.items():
        str_key = f"{key[0]}:{key[2]} <-> {key[1]}:{key[3]} (proto={key[4]})"
        str_flows[str_key] = pkts

    return {
        'packets': parsed_packets,
        'flows': str_flows,
        'raw_flows': dict(flows),
        'metadata': metadata,
        'tls_flows': {str(k): v for k, v in tls_flows.items()},
    }


# ─── Per-Packet Extraction ──────────────────────────────────────────────────

def _extract_packet_data(pkt):
    """Extract comprehensive metadata fields from a single packet."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    data = {
        'timestamp': float(pkt.time),
        'src_ip': ip.src,
        'dst_ip': ip.dst,
        'protocol': ip.proto,
        'packet_length': len(pkt),
        'ip_length': ip.len,
        'ip_header_len': ip.ihl * 4,  # IP header length in bytes
        'ttl': ip.ttl,
        'flags': '',
        'src_port': 0,
        'dst_port': 0,
        'src_mac': '',
        'dst_mac': '',
        'tcp_header_len': 0,
        'tcp_window_size': 0,
        'payload_len': 0,
        'is_forward': True,  # Will be set by caller
    }

    # MAC addresses
    if pkt.haslayer(Ether):
        data['src_mac'] = pkt[Ether].src
        data['dst_mac'] = pkt[Ether].dst

    # TCP specifics
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        data['src_port'] = tcp.sport
        data['dst_port'] = tcp.dport
        data['flags'] = str(tcp.flags)
        data['protocol_name'] = 'TCP'
        data['tcp_header_len'] = tcp.dataofs * 4 if tcp.dataofs else 20
        data['tcp_window_size'] = tcp.window
        # Payload = IP total length - IP header - TCP header
        data['payload_len'] = max(0, ip.len - (ip.ihl * 4) - data['tcp_header_len'])

    # UDP specifics
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        data['src_port'] = udp.sport
        data['dst_port'] = udp.dport
        data['protocol_name'] = 'UDP'
        data['tcp_header_len'] = 8  # UDP header is always 8 bytes
        data['payload_len'] = max(0, udp.len - 8) if udp.len else 0

    # ICMP
    elif pkt.haslayer(ICMP):
        data['protocol_name'] = 'ICMP'
    else:
        data['protocol_name'] = f'OTHER({ip.proto})'

    # Total header length (IP + transport)
    data['header_len'] = data['ip_header_len'] + data['tcp_header_len']

    # DNS flag
    data['has_dns'] = pkt.haslayer(DNS)

    return data


# ─── TLS/SSL Extraction ─────────────────────────────────────────────────────

def _extract_tls_metadata(pkt, flow_key, pkt_data, tls_flows):
    """
    Extract TLS handshake metadata from raw packet payload.
    Parses ClientHello/ServerHello to get ciphersuites, extensions, and compute JA3.
    """
    if not pkt.haslayer(TCP):
        return

    # Get TCP payload
    tcp = pkt[TCP]
    payload = bytes(tcp.payload) if tcp.payload else b''

    if len(payload) < 6:
        return

    # Check for TLS handshake record
    content_type = payload[0]
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
        return

    try:
        tls_version = struct.unpack('!H', payload[1:3])[0]
        record_length = struct.unpack('!H', payload[3:5])[0]
        handshake_type = payload[5]

        tls_info = tls_flows[flow_key]

        if handshake_type == TLS_HANDSHAKE_CLIENT_HELLO and not tls_info['client_hello']:
            tls_info['client_hello'] = True
            tls_info['handshake_start'] = pkt_data['timestamp']
            tls_info['tls_version'] = TLS_VERSIONS.get(tls_version, f'0x{tls_version:04x}')

            # Parse ClientHello for JA3
            parsed = _parse_client_hello(payload[5:5 + record_length])
            if parsed:
                tls_info['ciphersuites'] = parsed.get('ciphersuites', [])
                tls_info['extensions'] = parsed.get('extensions', [])
                tls_info['ja3'] = parsed.get('ja3_hash', '')

        elif handshake_type == TLS_HANDSHAKE_SERVER_HELLO and not tls_info['server_hello']:
            tls_info['server_hello'] = True
            tls_info['handshake_end'] = pkt_data['timestamp']

            # Parse ServerHello for JA3S
            parsed = _parse_server_hello(payload[5:5 + record_length])
            if parsed:
                tls_info['ja3s'] = parsed.get('ja3s_hash', '')

    except (struct.error, IndexError):
        pass


def _parse_client_hello(data):
    """Parse TLS ClientHello to extract ciphersuites and extensions for JA3."""
    try:
        if len(data) < 38:
            return None

        # Skip: handshake type(1) + length(3) + version(2) + random(32)
        offset = 1 + 3 + 2 + 32

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        # Cipher suites
        cipher_len = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2
        ciphersuites = []
        for i in range(0, cipher_len, 2):
            cs = struct.unpack('!H', data[offset + i:offset + i + 2])[0]
            # Skip GREASE values
            if (cs & 0x0f0f) != 0x0a0a:
                ciphersuites.append(cs)
        offset += cipher_len

        # Compression methods
        comp_len = data[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        ext_lengths = []
        if offset + 2 <= len(data):
            ext_total_len = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= ext_end:
                ext_type = struct.unpack('!H', data[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', data[offset + 2:offset + 4])[0]
                if (ext_type & 0x0f0f) != 0x0a0a:  # Skip GREASE
                    extensions.append(ext_type)
                    ext_lengths.append(ext_len)
                offset += 4 + ext_len

        # Compute JA3 hash
        tls_ver = struct.unpack('!H', data[4:6])[0]
        ja3_str = f"{tls_ver},{'-'.join(map(str, ciphersuites))},{'-'.join(map(str, extensions))}"
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        return {
            'ciphersuites': ciphersuites,
            'extensions': extensions,
            'ext_lengths': ext_lengths,
            'ja3_hash': ja3_hash,
        }

    except (struct.error, IndexError):
        return None


def _parse_server_hello(data):
    """Parse TLS ServerHello for JA3S hash."""
    try:
        if len(data) < 38:
            return None

        offset = 1 + 3 + 2 + 32

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        # Selected cipher suite
        cipher = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2

        # Compression
        offset += 1

        # Extensions
        extensions = []
        if offset + 2 <= len(data):
            ext_total_len = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len
            while offset + 4 <= ext_end:
                ext_type = struct.unpack('!H', data[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', data[offset + 2:offset + 4])[0]
                extensions.append(ext_type)
                offset += 4 + ext_len

        tls_ver = struct.unpack('!H', data[4:6])[0]
        ja3s_str = f"{tls_ver},{cipher},{'-'.join(map(str, extensions))}"
        ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()

        return {'ja3s_hash': ja3s_hash}

    except (struct.error, IndexError):
        return None
