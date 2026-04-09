"""
The Obsidian Lens — Identity Database v2
SQLite-backed persistent storage for behavioral fingerprints.

BEHAVIORAL CODENAME ENGINE:
- Each new identity receives a unique codename derived from its behavioral cluster
- Codenames are persistent — if the same behavior is seen from a new device/IP/browser,
  the system matches it to the existing identity using cosine similarity on a 10D behavior vector
- Threshold: 0.85 cosine similarity (within ~1 std dev of natural human behavioral variance)
"""

import sqlite3
import os
import json
import math
from datetime import datetime
from config import BASE_DIR

DB_PATH = os.path.join(BASE_DIR, 'obsidian_identities.db')

# ─── Behavioral Name Components ──────────────────────────────────────────────
# Adjectives derived from TEMPORAL behavior (IAT, duration, burst patterns)
TEMPORAL_ADJECTIVES = [
    "Swift", "Shadow", "Silent", "Steady", "Rapid", "Slow", "Erratic", "Calm",
    "Burst", "Idle", "Dark", "Bright", "Dim", "Hollow", "Deep", "Sharp",
    "Ghost", "Echo", "Drift", "Pulse"
]

# Nouns derived from VOLUMETRIC / PROTOCOL behavior (payload size, encryption ratio, upload/download)
VOLUMETRIC_NOUNS = [
    "Tide", "Phantom", "Stone", "Wave", "Cipher", "Veil", "Surge", "Hollow",
    "Flux", "Drift", "Beacon", "Mirage", "Specter", "Raven", "Ridge", "Delta",
    "Ember", "Frost", "Vertex", "Nexus"
]


def _get_conn():
    """Get a connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist. Handles schema migration."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS identities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_label  TEXT NOT NULL,
            codename        TEXT DEFAULT '',
            mac_address     TEXT DEFAULT '',
            ja3_hash        TEXT DEFAULT '',
            behavior_vector TEXT DEFAULT '',
            category        TEXT NOT NULL DEFAULT 'white',
            threat_type     TEXT DEFAULT 'Safe Traffic',
            is_blocked      INTEGER NOT NULL DEFAULT 0,
            confidence      REAL DEFAULT 0.0,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            flow_count      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS identity_ips (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id     INTEGER NOT NULL,
            ip_address      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS identity_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id     INTEGER NOT NULL,
            event_type      TEXT NOT NULL,
            details         TEXT DEFAULT '',
            timestamp       TEXT NOT NULL,
            FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_ips_unique
            ON identity_ips(identity_id, ip_address);
    """)

    # Schema migration: add new columns if they don't exist (for existing databases)
    existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(identities)").fetchall()]
    if 'codename' not in existing_cols:
        conn.execute("ALTER TABLE identities ADD COLUMN codename TEXT DEFAULT ''")
    if 'behavior_vector' not in existing_cols:
        conn.execute("ALTER TABLE identities ADD COLUMN behavior_vector TEXT DEFAULT ''")

    conn.commit()
    conn.close()


# ─── Behavioral Fingerprint Engine ───────────────────────────────────────────

def _cosine_similarity(v1, v2):
    """Compute cosine similarity between two equal-length numeric vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    mag1 = math.sqrt(sum(a * a for a in v1))
    mag2 = math.sqrt(sum(b * b for b in v2))
    if mag1 == 0 or mag2 == 0:
        return 0.0
    return dot / (mag1 * mag2)


def _generate_codename(behavior_vector, category):
    """
    Generate a human-readable codename from the behavior vector.
    The adjective is seeded from temporal features (indices 0-4).
    The noun is seeded from volumetric features (indices 5-9).
    Malicious identities get a 'dark' prefix.
    """
    if not behavior_vector or len(behavior_vector) < 10:
        import random
        adj = random.choice(TEMPORAL_ADJECTIVES)
        noun = random.choice(VOLUMETRIC_NOUNS)
    else:
        # Use temporal cluster mean (first 5 dims) to pick adjective
        temporal_seed = int(abs(sum(behavior_vector[:5]) * 1000)) % len(TEMPORAL_ADJECTIVES)
        # Use volumetric cluster mean (next 5 dims) to pick noun
        volumetric_seed = int(abs(sum(behavior_vector[5:10]) * 1000)) % len(VOLUMETRIC_NOUNS)
        adj = TEMPORAL_ADJECTIVES[temporal_seed]
        noun = VOLUMETRIC_NOUNS[volumetric_seed]

    if category == 'black':
        return f"THREAT-{adj}{noun}"
    return f"{adj}{noun}"


def find_similar_identity(conn, behavior_vector, threshold=0.85):
    """
    Search all known identities for one whose behavior_vector is
    within cosine similarity threshold of the given vector.
    Returns identity_id if found, else None.
    """
    if not behavior_vector:
        return None

    rows = conn.execute(
        "SELECT id, behavior_vector FROM identities WHERE behavior_vector != '' AND behavior_vector IS NOT NULL"
    ).fetchall()

    best_id = None
    best_sim = 0.0

    for row in rows:
        try:
            stored_vec = json.loads(row['behavior_vector'])
            sim = _cosine_similarity(behavior_vector, stored_vec)
            if sim > best_sim:
                best_sim = sim
                best_id = row['id']
        except (json.JSONDecodeError, TypeError):
            continue

    if best_sim >= threshold:
        print(f"[IDENTITY] Behavioral match found (similarity={best_sim:.3f}) → reusing identity #{best_id}")
        return best_id
    return None


# ─── Identity CRUD ──────────────────────────────────────────────────────


def upsert_identity(src_ip, dst_ip, category, threat_type, confidence,
                    mac_address='', ja3_hash='', analysis_id='', behavior_vector=None):
    """
    Insert or update an identity based on behavioral fingerprint.
    Priority order for matching:
      1. JA3 hash (cryptographic device fingerprint)
      2. MAC address (hardware fingerprint)  
      3. Behavioral vector cosine similarity (cross-device tracking)
      4. Source IP fallback
    If no match is found, a new identity with a behavioral codename is created.
    """
    conn = _get_conn()
    now = datetime.now().isoformat()
    identity_id = None
    bvec_str = json.dumps(behavior_vector) if behavior_vector else ''

    # Priority 1: JA3 hash match
    if ja3_hash:
        row = conn.execute(
            "SELECT id FROM identities WHERE ja3_hash = ? AND ja3_hash != ''",
            (ja3_hash,)
        ).fetchone()
        if row:
            identity_id = row['id']
            print(f"[IDENTITY] Matched via JA3 hash → #{identity_id}")

    # Priority 2: MAC address match
    if identity_id is None and mac_address:
        row = conn.execute(
            "SELECT id FROM identities WHERE mac_address = ? AND mac_address != ''",
            (mac_address,)
        ).fetchone()
        if row:
            identity_id = row['id']
            print(f"[IDENTITY] Matched via MAC address → #{identity_id}")

    # Priority 3: Behavioral vector cosine similarity (cross-device tracking)
    if identity_id is None and behavior_vector:
        identity_id = find_similar_identity(conn, behavior_vector, threshold=0.85)
        if identity_id:
            print(f"[IDENTITY] Cross-device match via behavior fingerprint → #{identity_id}")

    # Priority 4: IP fallback
    if identity_id is None:
        row = conn.execute(
            "SELECT identity_id FROM identity_ips WHERE ip_address = ?",
            (src_ip,)
        ).fetchone()
        if row:
            identity_id = row['identity_id']
            print(f"[IDENTITY] Matched via IP address → #{identity_id}")

    if identity_id is not None:
        # Update existing identity safely
        # Don't let a safe classification overwrite a confirmed threat
        update_vec = bvec_str if bvec_str else 'behavior_vector'
        conn.execute("""
            UPDATE identities
            SET last_seen = ?,
                confidence = MAX(confidence, ?),
                category = CASE WHEN category = 'black' THEN 'black' ELSE ? END,
                threat_type = CASE WHEN category = 'black' THEN threat_type ELSE ? END,
                flow_count = flow_count + 1,
                behavior_vector = CASE WHEN ? != '' THEN ? ELSE behavior_vector END
            WHERE id = ?
        """, (now, confidence, category, threat_type, bvec_str, bvec_str, identity_id))
    else:
        # Create new identity with behavioral codename
        codename = _generate_codename(behavior_vector, category)

        # Ensure codename is unique — add numeric suffix if taken
        existing = conn.execute(
            "SELECT id FROM identities WHERE codename = ?", (codename,)
        ).fetchone()
        if existing:
            count = conn.execute("SELECT COUNT(*) as c FROM identities").fetchone()['c']
            codename = f"{codename}-{count + 1}"

        cursor = conn.execute("""
            INSERT INTO identities
                (identity_label, codename, mac_address, ja3_hash, behavior_vector,
                 category, threat_type, confidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (codename, codename, mac_address, ja3_hash, bvec_str,
              category, threat_type, confidence, now, now))
        identity_id = cursor.lastrowid
        print(f"[IDENTITY] New identity created: '{codename}' (#{identity_id})")

    # Upsert IP mappings (track all IPs this identity ever used)
    for ip in [src_ip, dst_ip]:
        if ip:
            conn.execute("""
                INSERT INTO identity_ips (identity_id, ip_address, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(identity_id, ip_address) DO UPDATE SET last_seen = ?
            """, (identity_id, ip, now, now))

    # Log event
    conn.execute("""
        INSERT INTO identity_events (identity_id, event_type, details, timestamp)
        VALUES (?, 'analysis', ?, ?)
    """, (identity_id,
          json.dumps({'analysis_id': analysis_id, 'category': category,
                      'threat_type': threat_type}),
          now))

    conn.commit()
    conn.close()
    return identity_id


def block_identity(identity_id):
    """Block an identity from the network."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute("UPDATE identities SET is_blocked = 1 WHERE id = ?", (identity_id,))
    conn.execute("""
        INSERT INTO identity_events (identity_id, event_type, details, timestamp)
        VALUES (?, 'blocked', 'Identity blocked by administrator', ?)
    """, (identity_id, now))
    conn.commit()
    conn.close()


def unblock_identity(identity_id):
    """Unblock an identity."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute("UPDATE identities SET is_blocked = 0 WHERE id = ?", (identity_id,))
    conn.execute("""
        INSERT INTO identity_events (identity_id, event_type, details, timestamp)
        VALUES (?, 'unblocked', 'Identity unblocked by administrator', ?)
    """, (identity_id, now))
    conn.commit()
    conn.close()


def get_all_identities():
    """Get all identities with their associated IPs."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT * FROM identities ORDER BY last_seen DESC
    """).fetchall()

    identities = []
    for row in rows:
        ips = conn.execute("""
            SELECT ip_address, last_seen FROM identity_ips
            WHERE identity_id = ? ORDER BY last_seen DESC
        """, (row['id'],)).fetchall()

        identities.append({
            'id': row['id'],
            'identity_label': row['codename'] or row['identity_label'],
            'codename': row['codename'],
            'mac_address': row['mac_address'],
            'ja3_hash': row['ja3_hash'],
            'category': row['category'],
            'threat_type': row['threat_type'],
            'is_blocked': bool(row['is_blocked']),
            'confidence': row['confidence'],
            'first_seen': row['first_seen'],
            'last_seen': row['last_seen'],
            'flow_count': row['flow_count'],
            'associated_ips': [ip['ip_address'] for ip in ips],
        })

    conn.close()
    return identities


def get_identity(identity_id):
    """Get a single identity with full details."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
    if not row:
        conn.close()
        return None

    ips = conn.execute(
        "SELECT ip_address, last_seen FROM identity_ips WHERE identity_id = ?",
        (identity_id,)
    ).fetchall()

    events = conn.execute(
        "SELECT * FROM identity_events WHERE identity_id = ? ORDER BY timestamp DESC LIMIT 20",
        (identity_id,)
    ).fetchall()

    result = {
        'id': row['id'],
        'identity_label': row['codename'] or row['identity_label'],
        'codename': row['codename'],
        'mac_address': row['mac_address'],
        'ja3_hash': row['ja3_hash'],
        'category': row['category'],
        'threat_type': row['threat_type'],
        'is_blocked': bool(row['is_blocked']),
        'confidence': row['confidence'],
        'first_seen': row['first_seen'],
        'last_seen': row['last_seen'],
        'flow_count': row['flow_count'],
        'associated_ips': [ip['ip_address'] for ip in ips],
        'events': [{'event_type': e['event_type'], 'details': e['details'],
                     'timestamp': e['timestamp']} for e in events],
    }
    conn.close()
    return result


def get_network_health():
    """Compute detailed network health using multi-factor weighted scoring."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM identities").fetchone()['c']
    white = conn.execute("SELECT COUNT(*) as c FROM identities WHERE category = 'white'").fetchone()['c']
    black = conn.execute("SELECT COUNT(*) as c FROM identities WHERE category = 'black'").fetchone()['c']
    blocked = conn.execute("SELECT COUNT(*) as c FROM identities WHERE is_blocked = 1").fetchone()['c']
    blocked_white = conn.execute("SELECT COUNT(*) as c FROM identities WHERE category = 'white' AND is_blocked = 1").fetchone()['c']
    blocked_black = conn.execute("SELECT COUNT(*) as c FROM identities WHERE category = 'black' AND is_blocked = 1").fetchone()['c']

    avg_conf = conn.execute(
        "SELECT AVG(confidence) as avg_c FROM identities WHERE category = 'black' AND is_blocked = 0"
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
    """Clear all identity data."""
    conn = _get_conn()
    conn.executescript("""
        DELETE FROM identity_events;
        DELETE FROM identity_ips;
        DELETE FROM identities;
    """)
    conn.commit()
    conn.close()


# Initialize DB on import
init_db()
