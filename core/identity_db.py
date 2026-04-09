"""
The Obsidian Lens — Identity Database
SQLite-backed persistent storage for behavioral fingerprints.
Maps multiple IPs to unified user identities and tracks block status.
"""

import sqlite3
import os
import json
from datetime import datetime
from config import BASE_DIR

DB_PATH = os.path.join(BASE_DIR, 'obsidian_identities.db')


def _get_conn():
    """Get a connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS identities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_label  TEXT NOT NULL,
            mac_address     TEXT DEFAULT '',
            ja3_hash        TEXT DEFAULT '',
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
    conn.commit()
    conn.close()


# ─── Identity CRUD ──────────────────────────────────────────────────────


def upsert_identity(src_ip, dst_ip, category, threat_type, confidence,
                    mac_address='', ja3_hash='', analysis_id=''):
    """
    Insert or update an identity based on behavioral fingerprint.
    If an identity with the same ja3_hash or mac_address exists, update it.
    Otherwise create a new identity.
    """
    conn = _get_conn()
    now = datetime.now().isoformat()
    identity_id = None

    # Try to find existing identity by ja3 or mac
    if ja3_hash:
        row = conn.execute(
            "SELECT id FROM identities WHERE ja3_hash = ? AND ja3_hash != ''",
            (ja3_hash,)
        ).fetchone()
        if row:
            identity_id = row['id']

    if identity_id is None and mac_address:
        row = conn.execute(
            "SELECT id FROM identities WHERE mac_address = ? AND mac_address != ''",
            (mac_address,)
        ).fetchone()
        if row:
            identity_id = row['id']

    # Fallback: check if src_ip is already tracked
    if identity_id is None:
        row = conn.execute("""
            SELECT identity_id FROM identity_ips WHERE ip_address = ?
        """, (src_ip,)).fetchone()
        if row:
            identity_id = row['identity_id']

    if identity_id is not None:
        # Update existing identity safely. Don't let a normal flow erase a malicious classification.
        conn.execute("""
            UPDATE identities
            SET last_seen = ?, 
                confidence = MAX(confidence, ?), 
                category = CASE WHEN category = 'black' THEN 'black' ELSE ? END, 
                threat_type = CASE WHEN category = 'black' THEN threat_type ELSE ? END,
                flow_count = flow_count + 1
            WHERE id = ?
        """, (now, confidence, category, threat_type, identity_id))
    else:
        # Create new identity
        label_prefix = "MAL" if category == "black" else "USR"
        cursor = conn.execute("""
            INSERT INTO identities
                (identity_label, mac_address, ja3_hash, category, threat_type,
                 confidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (f"{label_prefix}-PENDING", mac_address, ja3_hash,
              category, threat_type, confidence, now, now))
        identity_id = cursor.lastrowid

        # Update label with ID
        label = f"{label_prefix}-{identity_id:04d}"
        conn.execute("UPDATE identities SET identity_label = ? WHERE id = ?",
                      (label, identity_id))

    # Upsert IP mappings
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
            'identity_label': row['identity_label'],
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
        'identity_label': row['identity_label'],
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

    # Get average confidence of unblocked black users (severity indicator)
    avg_conf = conn.execute(
        "SELECT AVG(confidence) as avg_c FROM identities WHERE category = 'black' AND is_blocked = 0"
    ).fetchone()['avg_c'] or 0.0
    conn.close()

    active_threats = max(0, black - blocked_black)

    if total == 0:
        score = 100
    else:
        # Start at 100, subtract penalties
        score = 100.0

        # Factor 1: Active threat ratio (0-40 points penalty)
        # Each unblocked threat costs proportionally more when there are fewer total identities
        threat_ratio = active_threats / max(total, 1)
        score -= threat_ratio * 40

        # Factor 2: Threat severity (0-20 points penalty)
        # High-confidence threats are more dangerous
        if active_threats > 0:
            severity_penalty = avg_conf * 20 * min(active_threats, 5) / 5
            score -= severity_penalty

        # Factor 3: Black-to-white ratio (0-15 points penalty)
        if white + black > 0:
            contamination = black / (white + black)
            score -= contamination * 15

        # Factor 4: Mitigation credit — blocked threats restore some health
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
    """Clear all identity data. For testing only."""
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
