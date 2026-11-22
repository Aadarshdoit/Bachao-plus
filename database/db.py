"""
BACHAO+ Database Engine
Handles SQLite connection management, schema initialization, indexes,
parameterized queries, and rate-limiting storage for the entire platform.
"""

import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = BASE_DIR / "database"
DB_PATH = DB_DIR / "bachao.db"
UPLOADS_DIR = BASE_DIR / "assets" / "uploads"


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create and return a SQLite database connection with row factory and timeout enabled."""
    target_path = db_path or DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent read performance and foreign keys
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize complete database schema with indexes and defensive constraints."""
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Users table (Authentication & RBAC)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Student',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    # 2. Central Security Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            source_ip TEXT DEFAULT '127.0.0.1'
        )
    """)

    # 3. Campus Safety Incidents table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campus_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            username TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT,
            image_path TEXT,
            is_sos INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Submitted',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_by TEXT,
            resolution_notes TEXT
        )
    """)

    # 4. Phishing & Scam Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phishing_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            target_type TEXT NOT NULL,
            target_content TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators_json TEXT,
            is_heuristic_only INTEGER DEFAULT 1
        )
    """)

    # 5. Password Audits table (Anonymized stats; never stores passwords)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            entropy_bits REAL NOT NULL,
            score INTEGER NOT NULL,
            pwned_match INTEGER NOT NULL DEFAULT 0,
            pwned_count INTEGER DEFAULT 0
        )
    """)

    # 6. Login Rate-Limiting & Brute-Force Defense table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_rate_limits (
            identifier TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 0,
            last_attempt TEXT NOT NULL,
            locked_until TEXT
        )
    """)

    # Performance & Lookups Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_user ON campus_incidents(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON campus_incidents(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_phishing_ts ON phishing_scans(timestamp)")

    conn.commit()
    conn.close()

    # Bootstrap initial admin if environment variables are provided
    bootstrap_admin_from_env(db_path)


def bootstrap_admin_from_env(db_path: Optional[Path] = None) -> None:
    """Safe bootstrap of initial admin account using environment variables."""
    admin_user = os.getenv("ADMIN_USERNAME")
    admin_pass = os.getenv("ADMIN_PASSWORD")
    admin_email = os.getenv("ADMIN_EMAIL", "admin@campus.defence")

    if admin_user and admin_pass:
        from utils.security import hash_password

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (admin_user.strip(),))
        existing = cursor.fetchone()

        if not existing:
            pwd_hash, salt = hash_password(admin_pass)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, 'Admin', ?)
                """,
                (admin_user.strip(), admin_email.strip().lower(), pwd_hash, salt, now)
            )
            evt_id = f"EVT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            cursor.execute(
                """
                INSERT INTO security_events (event_id, event_type, timestamp, user_id, severity, category, description)
                VALUES (?, 'USER_REGISTERED', ?, ?, 'INFO', 'ACCESS', 'Initial administrator initialized via environment configuration')
                """,
                (evt_id, now, admin_user.strip())
            )
            conn.commit()

        conn.close()


# ---------------------------------------------------------------------------
# User Authentication & RBAC Database Operations
# ---------------------------------------------------------------------------
def create_user(username: str, email: str, password_hash: str, salt: str, role: str = "Student") -> Tuple[bool, str]:
    """Register a new user with hashed credentials and assigned role."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username.strip(), email.strip().lower(), password_hash, salt, role, now)
        )
        conn.commit()
        return True, "User registered successfully."
    except sqlite3.IntegrityError as e:
        err_msg = str(e).lower()
        if "username" in err_msg:
            return False, "Username is already registered."
        elif "email" in err_msg:
            return False, "Email address is already registered."
        return False, "Account with this identifier already exists."
    except Exception as e:
        return False, f"Registration failed: {str(e)}"
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Fetch user record by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Fetch user record by email address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_last_login(user_id: int) -> None:
    """Update last login timestamp upon successful authentication."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
    conn.commit()
    conn.close()


def has_admin_user() -> bool:
    """Check if at least one Admin account exists in the platform."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'Admin'")
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0


def count_users() -> int:
    """Return total registered users count."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_all_users() -> List[Dict[str, Any]]:
    """Return list of all registered users (sanitized for admin directory)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at, last_login FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Brute-Force Rate Limiting Operations
# ---------------------------------------------------------------------------
def check_login_rate_limit(identifier: str, max_attempts: int = 5, lockout_minutes: int = 5) -> Tuple[bool, str]:
    """
    Check if an identifier is locked due to excessive failed attempts.
    Returns (is_allowed, reason_message).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()

    cursor.execute("SELECT attempts, last_attempt, locked_until FROM login_rate_limits WHERE identifier = ?", (identifier,))
    record = cursor.fetchone()

    if record and record["locked_until"]:
        try:
            locked_until_dt = datetime.strptime(record["locked_until"], "%Y-%m-%d %H:%M:%S")
            if now < locked_until_dt:
                wait_secs = int((locked_until_dt - now).total_seconds())
                wait_mins = (wait_secs // 60) + 1
                conn.close()
                return False, f"Account temporarily locked due to multiple failed login attempts. Please retry in {wait_mins} minute(s)."
        except Exception:
            pass

    conn.close()
    return True, ""


def record_failed_login_attempt(identifier: str, max_attempts: int = 5, lockout_minutes: int = 5) -> int:
    """
    Record a failed login attempt for an identifier and apply lockout if threshold exceeded.
    Returns current failure count.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT attempts FROM login_rate_limits WHERE identifier = ?", (identifier,))
    record = cursor.fetchone()

    if record:
        new_attempts = record["attempts"] + 1
        locked_until_str = None
        if new_attempts >= max_attempts:
            locked_until_dt = now + timedelta(minutes=lockout_minutes)
            locked_until_str = locked_until_dt.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            UPDATE login_rate_limits 
            SET attempts = ?, last_attempt = ?, locked_until = ?
            WHERE identifier = ?
            """,
            (new_attempts, now_str, locked_until_str, identifier)
        )
    else:
        new_attempts = 1
        cursor.execute(
            """
            INSERT INTO login_rate_limits (identifier, attempts, last_attempt, locked_until)
            VALUES (?, 1, ?, NULL)
            """,
            (identifier, now_str)
        )

    conn.commit()
    conn.close()
    return new_attempts


def reset_failed_login_attempts(identifier: str) -> None:
    """Reset failed login count upon successful authentication."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_rate_limits WHERE identifier = ?", (identifier,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Central Security Events Operations
# ---------------------------------------------------------------------------
def insert_event(
    event_type: str,
    severity: str,
    category: str,
    description: str,
    user_id: Optional[str] = None,
    source_ip: str = "127.0.0.1"
) -> str:
    """Insert a security event into the central event repository."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_id = f"EVT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    cursor.execute(
        """
        INSERT INTO security_events (event_id, event_type, timestamp, user_id, severity, category, description, source_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, event_type, now, user_id or "ANONYMOUS", severity.upper(), category.upper(), description, source_ip)
    )
    conn.commit()
    conn.close()
    return event_id


def get_recent_events(limit: int = 20) -> List[Dict[str, Any]]:
    """Fetch the most recent security events."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT event_id, event_type, timestamp, user_id, severity, category, description, source_ip
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Phishing & Scam Scans Operations
# ---------------------------------------------------------------------------
def record_phishing_scan(
    target_type: str,
    target_content: str,
    risk_score: int,
    risk_level: str,
    indicators_json: str,
    user_id: Optional[str] = None
) -> str:
    """Store phishing diagnostic scan results."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_id = f"SCN-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    cursor.execute(
        """
        INSERT INTO phishing_scans (scan_id, timestamp, user_id, target_type, target_content, risk_score, risk_level, indicators_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_id, now, user_id or "ANONYMOUS", target_type, target_content, risk_score, risk_level, indicators_json)
    )
    conn.commit()
    conn.close()
    return scan_id


def count_phishing_scans() -> int:
    """Return count of total scans performed."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM phishing_scans")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def count_high_risk_threats() -> int:
    """Count high or critical phishing threats detected."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM phishing_scans WHERE risk_level IN ('High', 'Critical')")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_threat_distribution() -> Dict[str, int]:
    """Return counts of phishing scans grouped by risk level."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT risk_level, COUNT(*) as count FROM phishing_scans GROUP BY risk_level")
    rows = cursor.fetchall()
    conn.close()
    dist = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in rows:
        if r["risk_level"] in dist:
            dist[r["risk_level"]] = r["count"]
    return dist


# ---------------------------------------------------------------------------
# Password Safety Audit Operations
# ---------------------------------------------------------------------------
def record_password_audit(entropy_bits: float, score: int, pwned_match: bool, pwned_count: int, user_id: Optional[str] = None) -> None:
    """Record anonymized password audit statistics without storing candidate passwords."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        """
        INSERT INTO password_audits (timestamp, user_id, entropy_bits, score, pwned_match, pwned_count)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (now, user_id or "ANONYMOUS", entropy_bits, score, 1 if pwned_match else 0, pwned_count)
    )
    conn.commit()
    conn.close()


def count_pwned_matches() -> int:
    """Count how many audited passwords matched known breach datasets."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM password_audits WHERE pwned_match = 1")
    count = cursor.fetchone()[0]
    conn.close()
    return count


# ---------------------------------------------------------------------------
# Campus Safety Incidents Operations
# ---------------------------------------------------------------------------
def create_campus_incident(
    username: str,
    category: str,
    description: str,
    location: Optional[str] = None,
    image_path: Optional[str] = None,
    is_sos: bool = False,
    user_id: Optional[int] = None
) -> str:
    """Submit a new campus incident report with initial status 'Submitted'."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prefix = "SOS" if is_sos else "INC"
    incident_id = f"{prefix}-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    cursor.execute(
        """
        INSERT INTO campus_incidents (
            incident_id, user_id, username, category, description, location, 
            image_path, is_sos, status, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Submitted', ?, ?)
        """,
        (
            incident_id, user_id, username.strip(), category, description.strip(),
            location or "Unspecified Campus Location",
            image_path, 1 if is_sos else 0, now, now
        )
    )
    conn.commit()
    conn.close()
    return incident_id


def get_campus_incidents(username: Optional[str] = None, is_admin: bool = False) -> List[Dict[str, Any]]:
    """
    Retrieve campus incidents.
    Students strictly see only their own reports.
    Campus Security and Admins see all reports across the institution.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    if is_admin:
        cursor.execute(
            """
            SELECT * FROM campus_incidents 
            ORDER BY is_sos DESC, id DESC
            """
        )
    else:
        # Strictly enforce user filtering for non-officers
        safe_user = (username or "").strip()
        cursor.execute(
            """
            SELECT * FROM campus_incidents 
            WHERE username = ?
            ORDER BY id DESC
            """,
            (safe_user,)
        )

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_incident_status(incident_id: str, new_status: str, resolved_by: str, notes: Optional[str] = None) -> bool:
    """Update incident status and attach resolution remarks."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
        UPDATE campus_incidents 
        SET status = ?, updated_at = ?, resolved_by = ?, resolution_notes = ?
        WHERE incident_id = ?
        """,
        (new_status, now, resolved_by.strip(), notes or "", incident_id)
    )
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return changed


def count_campus_incidents() -> int:
    """Return total count of campus incidents reported."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM campus_incidents")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def count_resolved_incidents() -> int:
    """Return count of incidents marked as Resolved."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM campus_incidents WHERE status = 'Resolved'")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_incident_status_distribution() -> Dict[str, int]:
    """Return count distribution of incidents by status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM campus_incidents GROUP BY status")
    rows = cursor.fetchall()
    conn.close()
    dist = {"Submitted": 0, "Acknowledged": 0, "In Progress": 0, "Resolved": 0}
    for r in rows:
        st_name = r["status"]
        # Normalize legacy 'Reported' to 'Submitted' if any exist
        if st_name == "Reported":
            dist["Submitted"] = dist.get("Submitted", 0) + r["count"]
        elif st_name in dist:
            dist[st_name] += r["count"]
        else:
            dist[st_name] = r["count"]
    return dist


# ---------------------------------------------------------------------------
# Aggregated Dashboard Metrics
# ---------------------------------------------------------------------------
def get_dashboard_metrics() -> Dict[str, Any]:
    """Calculate and return verified real-time platform statistics."""
    return {
        "total_users": count_users(),
        "urls_analyzed": count_phishing_scans(),
        "high_risk_threats": count_high_risk_threats(),
        "pwned_matches": count_pwned_matches(),
        "incidents_reported": count_campus_incidents(),
        "incidents_resolved": count_resolved_incidents(),
    }


def seed_demo_data_if_empty() -> None:
    """Initialize schema and seed initial system events if database is empty."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM security_events")
    event_count = cursor.fetchone()[0]

    if event_count == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        initial_events = [
            (f"EVT-{datetime.now().strftime('%Y%m%d')}-000001", "SYSTEM_STARTUP", now, "SYSTEM", "INFO", "SYSTEM", "BACHAO+ Defence Platform initialized successfully", "127.0.0.1"),
            (f"EVT-{datetime.now().strftime('%Y%m%d')}-000002", "DATABASE_INITIALIZED", now, "SYSTEM", "INFO", "SYSTEM", "SQLite operational vaults mounted with foreign constraints and WAL mode", "127.0.0.1"),
            (f"EVT-{datetime.now().strftime('%Y%m%d')}-000003", "DEFENCE_BASELINE_SYNC", now, "SYSTEM", "INFO", "SECURITY", "Perimeter monitoring rules and phishing heuristics synchronized", "127.0.0.1"),
        ]
        cursor.executemany(
            """
            INSERT INTO security_events (event_id, event_type, timestamp, user_id, severity, category, description, source_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            initial_events
        )
        conn.commit()

    conn.close()
