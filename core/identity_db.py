"""
The Obsidian Lens — Identity Database v3
SQLite-backed persistent storage for behavioral fingerprints.

BEHAVIORAL CODENAME ENGINE:
- Each identity receives a unique codename derived from its behavioral cluster
- Maps Identities (Users) -> MAC Addresses (Devices) -> IP Addresses (Logical Allocations)
- Stores full behavioral fingerprints in flat JSON files to keep DB queries ultra-fast.
"""

import sqlite3
import os
import json
import math
from datetime import datetime
from config import BASE_DIR

DB_PATH = os.path.join(BASE_DIR, 'obsidian_identities.db')
FINGERPRINTS_DIR = os.path.join(BASE_DIR, 'data', 'fingerprints')
os.makedirs(FINGERPRINTS_DIR, exist_ok=True)

# ─── Behavioral Name Components ──────────────────────────────────────────────
TEMPORAL_ADJECTIVES = [
    "Swift", "Shadow", "Silent", "Steady", "Rapid", "Slow", "Erratic", "Calm",
    "Burst", "Idle", "Dark", "Bright", "Dim", "Hollow", "Deep", "Sharp",
    "Ghost", "Echo", "Drift", "Pulse"
]

VOLUMETRIC_NOUNS = [
    "Tide", "Phantom", "Stone", "Wave", "Cipher", "Veil", "Surge", "Hollow",
    "Flux", "Drift", "Beacon", "Mirage", "Specter", "Raven", "Ridge", "Delta",
    "Ember", "Frost", "Vertex", "Nexus"
]


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_label      TEXT NOT NULL,
            codename        TEXT DEFAULT '',
            fingerprint_file TEXT DEFAULT '',
            ja3_hash        TEXT DEFAULT '',
            category        TEXT NOT NULL DEFAULT 'white',
            threat_type     TEXT DEFAULT 'Safe Traffic',
            is_blocked      INTEGER NOT NULL DEFAULT 0,
            confidence      REAL DEFAULT 0.0,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            flow_count      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS mac_addresses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            mac_address     TEXT NOT NULL,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ip_addresses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_id          INTEGER NOT NULL,
            ip_address      TEXT NOT NULL,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            FOREIGN KEY (mac_id) REFERENCES mac_addresses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS identity_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            event_type      TEXT NOT NULL,
            details         TEXT DEFAULT '',
            timestamp       TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_mac_unique
            ON mac_addresses(user_id, mac_address);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_unique
            ON ip_addresses(mac_id, ip_address);
    """)
    conn.commit()
    conn.close()


def _cosine_similarity(v1, v2):
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    mag1 = math.sqrt(sum(a * a for a in v1))
    mag2 = math.sqrt(sum(b * b for b in v2))
    if mag1 == 0 or mag2 == 0:
        return 0.0
    return dot / (mag1 * mag2)


def _generate_codename(conn):
    """Generates sequential identities like User001, User002."""
    row = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()
    count = row['c'] if row else 0
    return f"User{count + 1:03d}"


def find_similar_identity(conn, behavior_vector, threshold=0.85):
    if not behavior_vector:
        return None

    rows = conn.execute("SELECT id, fingerprint_file FROM users WHERE fingerprint_file != ''").fetchall()

    best_id = None
    best_sim = 0.0

    for row in rows:
        filepath = os.path.join(FINGERPRINTS_DIR, row['fingerprint_file'])
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                stored_vec = data.get('behavior_vector')
                if stored_vec:
                    sim = _cosine_similarity(behavior_vector, stored_vec)
                    if sim > best_sim:
                        best_sim = sim
                        best_id = row['id']
        except Exception:
            continue

    if best_sim >= threshold:
        print(f"[IDENTITY] Behavioral match found (similarity={best_sim:.3f}) → reusing identity #{best_id}")
        return best_id
    return None


def upsert_identity(src_ip, dst_ip, category, threat_type, confidence,
                    mac_address='', ja3_hash='', analysis_id='', behavior_vector=None, full_features=None):
    conn = _get_conn()
    now = datetime.now().isoformat()
    user_id = None

    mac_address = mac_address or ""

    # Priority 1: JA3 Hash Match
    if ja3_hash:
        row = conn.execute("SELECT id FROM users WHERE ja3_hash = ? AND ja3_hash != ''", (ja3_hash,)).fetchone()
        if row:
            user_id = row['id']

    # Priority 2: MAC Match
    if user_id is None and mac_address:
        row = conn.execute("SELECT user_id FROM mac_addresses WHERE mac_address = ? AND mac_address != ''", (mac_address,)).fetchone()
        if row:
            user_id = row['user_id']

    # Priority 3: Cross-device Behavior Vector Cosine Sim
    if user_id is None and behavior_vector:
        user_id = find_similar_identity(conn, behavior_vector, threshold=0.85)

    # Priority 4: IP Fallback
    if user_id is None:
        row = conn.execute("SELECT m.user_id FROM ip_addresses ip JOIN mac_addresses m ON ip.mac_id = m.id WHERE ip.ip_address = ?", (src_ip,)).fetchone()
        if row:
            user_id = row['user_id']

    fingerprint_filename = ""
    # Update / Insert Root User
    if user_id is not None:
        user_row = conn.execute("SELECT fingerprint_file FROM users WHERE id = ?", (user_id,)).fetchone()
        fingerprint_filename = user_row['fingerprint_file'] if user_row and user_row['fingerprint_file'] else f"USER_{user_id}.json"
        
        conn.execute("""
            UPDATE users
            SET last_seen = ?,
                confidence = MAX(confidence, ?),
                category = CASE WHEN category = 'black' THEN 'black' ELSE ? END,
                threat_type = CASE WHEN category = 'black' THEN threat_type ELSE ? END,
                flow_count = flow_count + 1,
                fingerprint_file = ?
            WHERE id = ?
        """, (now, confidence, category, threat_type, fingerprint_filename, user_id))
    else:
        codename = _generate_codename(conn)

        fingerprint_filename = f"{codename}.json".replace(" ", "_").upper()
        
        cursor = conn.execute("""
            INSERT INTO users
                (user_label, codename, fingerprint_file, ja3_hash,
                 category, threat_type, confidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (codename, codename, fingerprint_filename, ja3_hash,
              category, threat_type, confidence, now, now))
        user_id = cursor.lastrowid
        # Safe filename ensuring unique ID if codename collision somehow bypassed
        fingerprint_filename = f"USER_{user_id}_{fingerprint_filename}"
        conn.execute("UPDATE users SET fingerprint_file = ? WHERE id = ?", (fingerprint_filename, user_id))
        print(f"[IDENTITY] New user identity created: '{codename}' (#{user_id})")

    # Upsert JSON File
    if full_features or behavior_vector:
        filepath = os.path.join(FINGERPRINTS_DIR, fingerprint_filename)
        data_to_save = {}
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data_to_save = json.load(f)
            except Exception:
                pass
        
        if behavior_vector:
            data_to_save['behavior_vector'] = behavior_vector
        if full_features:
            data_to_save['full_features'] = full_features
        data_to_save['last_updated'] = now
            
        with open(filepath, 'w') as f:
            json.dump(data_to_save, f, indent=4)

    # Upsert MAC Address
    conn.execute("""
        INSERT INTO mac_addresses (user_id, mac_address, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id, mac_address) DO UPDATE SET last_seen = ?
    """, (user_id, mac_address, now, now, now))

    mac_row = conn.execute("SELECT id FROM mac_addresses WHERE user_id = ? AND mac_address = ?", (user_id, mac_address)).fetchone()
    mac_id = mac_row['id']

    # Upsert IP Addresses mapped to this MAC
    for ip in [src_ip, dst_ip]:
        if ip:
            conn.execute("""
                INSERT INTO ip_addresses (mac_id, ip_address, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(mac_id, ip_address) DO UPDATE SET last_seen = ?
            """, (mac_id, ip, now, now, now))

    # Log event
    conn.execute("""
        INSERT INTO identity_events (user_id, event_type, details, timestamp)
        VALUES (?, 'analysis', ?, ?)
    """, (user_id,
          json.dumps({'analysis_id': analysis_id, 'category': category, 'threat_type': threat_type}),
          now))

    conn.commit()
    conn.close()
    return user_id


def block_identity(user_id):
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute("UPDATE users SET is_blocked = 1 WHERE id = ?", (user_id,))
    conn.execute("""
        INSERT INTO identity_events (user_id, event_type, details, timestamp)
        VALUES (?, 'blocked', 'Identity blocked by administrator', ?)
    """, (user_id, now))
    conn.commit()
    conn.close()


def unblock_identity(user_id):
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute("UPDATE users SET is_blocked = 0 WHERE id = ?", (user_id,))
    conn.execute("""
        INSERT INTO identity_events (user_id, event_type, details, timestamp)
        VALUES (?, 'unblocked', 'Identity unblocked by administrator', ?)
    """, (user_id, now))
    conn.commit()
    conn.close()


def get_all_identities():
    conn = _get_conn()
    users = conn.execute("SELECT * FROM users ORDER BY last_seen DESC").fetchall()

    results = []
    for u in users:
        uid = u['id']
        macs = conn.execute("SELECT id, mac_address FROM mac_addresses WHERE user_id = ?", (uid,)).fetchall()
        
        all_ips = set()
        primary_mac = ""
        
        for m in macs:
            if m['mac_address'] and not primary_mac:
                primary_mac = m['mac_address']
            ips = conn.execute("SELECT ip_address FROM ip_addresses WHERE mac_id = ? ORDER BY last_seen DESC", (m['id'],)).fetchall()
            for ip in ips:
                all_ips.add(ip['ip_address'])

        results.append({
            'id': uid,
            'identity_label': u['codename'] or u['user_label'],
            'codename': u['codename'],
            'mac_address': primary_mac, 
            'ja3_hash': u['ja3_hash'],
            'category': u['category'],
            'threat_type': u['threat_type'],
            'is_blocked': bool(u['is_blocked']),
            'confidence': u['confidence'],
            'first_seen': u['first_seen'],
            'last_seen': u['last_seen'],
            'flow_count': u['flow_count'],
            'associated_ips': list(all_ips),
            'fingerprint_file': u['fingerprint_file']
        })

    conn.close()
    return results


def get_identity(user_id):
    conn = _get_conn()
    u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not u:
        conn.close()
        return None

    macs = conn.execute("SELECT id, mac_address FROM mac_addresses WHERE user_id = ?", (user_id,)).fetchall()
    all_ips = set()
    mac_list = []
    for m in macs:
        if m['mac_address']:
            mac_list.append(m['mac_address'])
        ips = conn.execute("SELECT ip_address FROM ip_addresses WHERE mac_id = ?", (m['id'],)).fetchall()
        for ip in ips:
            all_ips.add(ip['ip_address'])

    events = conn.execute(
        "SELECT * FROM identity_events WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20",
        (user_id,)
    ).fetchall()

    result = {
        'id': u['id'],
        'identity_label': u['codename'] or u['user_label'],
        'codename': u['codename'],
        'mac_address': mac_list[0] if mac_list else "",
        'all_macs': mac_list,
        'ja3_hash': u['ja3_hash'],
        'category': u['category'],
        'threat_type': u['threat_type'],
        'is_blocked': bool(u['is_blocked']),
        'confidence': u['confidence'],
        'first_seen': u['first_seen'],
        'last_seen': u['last_seen'],
        'flow_count': u['flow_count'],
        'associated_ips': list(all_ips),
        'events': [{'event_type': e['event_type'], 'details': e['details'], 'timestamp': e['timestamp']} for e in events],
    }
    conn.close()
    return result


def get_network_health():
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    white = conn.execute("SELECT COUNT(*) as c FROM users WHERE category = 'white'").fetchone()['c']
    black = conn.execute("SELECT COUNT(*) as c FROM users WHERE category = 'black'").fetchone()['c']
    blocked = conn.execute("SELECT COUNT(*) as c FROM users WHERE is_blocked = 1").fetchone()['c']
    blocked_white = conn.execute("SELECT COUNT(*) as c FROM users WHERE category = 'white' AND is_blocked = 1").fetchone()['c']
    blocked_black = conn.execute("SELECT COUNT(*) as c FROM users WHERE category = 'black' AND is_blocked = 1").fetchone()['c']

    avg_conf = conn.execute(
        "SELECT AVG(confidence) as avg_c FROM users WHERE category = 'black' AND is_blocked = 0"
    ).fetchone()['avg_c'] or 0.0
    conn.close()

    active_threats = max(0, black - blocked_black)

    if total == 0:
        score = 100
    else:
        score = 100.0
        threat_ratio = active_threats / max(total, 1)
        score -= threat_ratio * 40
        if active_threats > 0:
            severity_penalty = avg_conf * 20 * min(active_threats, 5) / 5
            score -= severity_penalty
        if white + black > 0:
            contamination = black / (white + black)
            score -= contamination * 15
        if black > 0:
            mitigation = (blocked_black / black) * 10
            score += mitigation
        score = max(0, min(100, int(score)))

    return {
        'health_score': score,
        'total_identities': total,
        'white_count': white,
        'black_count': black,
        'blocked_count': blocked,
        'blocked_white': blocked_white,
        'blocked_black': blocked_black,
        'active_threats': active_threats,
        'avg_threat_confidence': round(avg_conf, 3),
    }


def clear_all():
    conn = _get_conn()
    conn.executescript("""
        DELETE FROM identity_events;
        DELETE FROM ip_addresses;
        DELETE FROM mac_addresses;
        DELETE FROM users;
    """)
    conn.commit()
    conn.close()
    
    # Also clear fingerprints
    for f in os.listdir(FINGERPRINTS_DIR):
        if f.endswith('.json'):
            try:
                os.remove(os.path.join(FINGERPRINTS_DIR, f))
            except:
                pass

init_db()
