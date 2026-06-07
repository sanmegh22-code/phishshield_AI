import sqlite3
import hashlib
import os
import json

DB_PATH = os.path.join(os.path.dirname(__file__), "phishshield.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ":" + kdf.hex()

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return kdf == key
    except Exception:
        return False

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 2. Threat History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT NOT NULL, -- URL, Email, QR
        target TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        classification TEXT NOT NULL, -- Safe, Suspicious, Phishing
        reasons TEXT NOT NULL, -- JSON string list of explanations
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
    """)
    
    # 3. Model Training Dataset Table (for retraining / user overrides)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dataset (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL,
        label INTEGER NOT NULL, -- 0 for Safe, 1 for Phishing
        source TEXT NOT NULL, -- 'system' or 'user'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Seed default Admin and User if not exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", hash_password("Admin@123"), "admin")
        )
        
    cursor.execute("SELECT id FROM users WHERE username = 'user'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("user", hash_password("User@123"), "user")
        )

    # Seed a basic set of URLs for model initialization if dataset is empty
    cursor.execute("SELECT COUNT(*) FROM dataset")
    if cursor.fetchone()[0] == 0:
        seed_urls = [
            # Legitimate (label = 0)
            ("https://google.com", 0, "system"),
            ("https://youtube.com", 0, "system"),
            ("https://facebook.com", 0, "system"),
            ("https://amazon.com", 0, "system"),
            ("https://apple.com", 0, "system"),
            ("https://microsoft.com", 0, "system"),
            ("https://netflix.com", 0, "system"),
            ("https://paypal.com", 0, "system"),
            ("https://github.com", 0, "system"),
            ("https://stackoverflow.com", 0, "system"),
            ("https://wikipedia.org", 0, "system"),
            ("https://linkedin.com", 0, "system"),
            # Phishing (label = 1)
            ("https://paypal-security-login.com", 1, "system"),
            ("https://verify-amazon-account-support.com", 1, "system"),
            ("https://netflix-billing-update-alert.com", 1, "system"),
            ("https://login.microsoft-security-auth.net", 1, "system"),
            ("https://apple-id-reset-password.org", 1, "system"),
            ("https://secure-chase-online-banking.com", 1, "system"),
            ("https://accounts-google-recovery.net", 1, "system"),
            ("https://secure-wellsfargo-login.com", 1, "system"),
            ("https://facebook-verification-badge.com", 1, "system"),
            ("https://instagram-copyright-infringement.com", 1, "system")
        ]
        cursor.executemany(
            "INSERT OR IGNORE INTO dataset (url, label, source) VALUES (?, ?, ?)",
            seed_urls
        )
        
    conn.commit()
    conn.close()

# User CRUD
def add_user(username, password, role='user'):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.strip(), hash_password(password), role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        return None

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    conn.close()
    return user

def get_all_users():
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role, created_at FROM users").fetchall()
    conn.close()
    return users

# Threat CRUD
def add_threat(user_id, scan_type, target, risk_score, classification, reasons):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO threat_history (user_id, type, target, risk_score, classification, reasons) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, scan_type, target, risk_score, classification, json.dumps(reasons))
    )
    conn.commit()
    threat_id = cursor.lastrowid
    conn.close()
    return threat_id

def get_threat_history(user_id=None, limit=100):
    conn = get_db_connection()
    if user_id:
        threats = conn.execute(
            "SELECT t.*, u.username FROM threat_history t LEFT JOIN users u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.created_at DESC LIMIT ?",
            (user_id, limit)
        ).fetchall()
    else:
        threats = conn.execute(
            "SELECT t.*, u.username FROM threat_history t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return threats

def get_threat_by_id(threat_id):
    conn = get_db_connection()
    threat = conn.execute(
        "SELECT t.*, u.username FROM threat_history t LEFT JOIN users u ON t.user_id = u.id WHERE t.id = ?",
        (threat_id,)
    ).fetchone()
    conn.close()
    return threat

def delete_threat(threat_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_history WHERE id = ?", (threat_id,))
    conn.commit()
    conn.close()

# Dataset CRUD
def add_dataset_item(url, label, source='user'):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO dataset (url, label, source) VALUES (?, ?, ?)",
            (url.strip(), label, source)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def get_dataset_items():
    conn = get_db_connection()
    items = conn.execute("SELECT url, label FROM dataset").fetchall()
    conn.close()
    return items

def get_dataset_count():
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM dataset").fetchone()[0]
    conn.close()
    return count

# Dashboard Statistics
def get_stats(user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query_suffix = " WHERE user_id = ?" if user_id else ""
    params = (user_id,) if user_id else ()
    
    # Total Scans
    cursor.execute("SELECT COUNT(*) FROM threat_history" + query_suffix, params)
    total_scans = cursor.fetchone()[0]
    
    # Scans by classification
    cursor.execute(
        "SELECT classification, COUNT(*) FROM threat_history" + query_suffix + " GROUP BY classification",
        params
    )
    class_counts = {r[0]: r[1] for r in cursor.fetchall()}
    safe_count = class_counts.get("Safe", 0)
    suspicious_count = class_counts.get("Suspicious", 0)
    phishing_count = class_counts.get("Phishing", 0)
    
    # Scans by Type
    cursor.execute(
        "SELECT type, COUNT(*) FROM threat_history" + query_suffix + " GROUP BY type",
        params
    )
    type_counts = {r[0]: r[1] for r in cursor.fetchall()}
    url_scans = type_counts.get("URL", 0)
    email_scans = type_counts.get("Email", 0)
    qr_scans = type_counts.get("QR", 0)
    
    # Recent activity timeline (last 7 entries)
    cursor.execute(
        "SELECT created_at, risk_score, classification FROM threat_history" + query_suffix + " ORDER BY created_at DESC LIMIT 7",
        params
    )
    recent_history = [{"date": r[0], "score": r[1], "class": r[2]} for r in cursor.fetchall()]
    
    conn.close()
    
    detection_rate = 0
    if total_scans > 0:
        detection_rate = round(((phishing_count + suspicious_count) / total_scans) * 100, 1)
        
    return {
        "total_scans": total_scans,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "phishing_count": phishing_count,
        "url_scans": url_scans,
        "email_scans": email_scans,
        "qr_scans": qr_scans,
        "detection_rate": detection_rate,
        "recent_history": recent_history
    }
