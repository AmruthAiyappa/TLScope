"""
SQLite Scan History Database Service for TLScope.

Maintains an educational audit log of recent scans with parameterized SQL queries,
advanced search/filtering, aggregate telemetry statistics, and individual record management.
"""

import json
import sqlite3
from typing import List, Dict, Any, Optional
from pathlib import Path


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Creates a configured SQLite database connection."""
    if db_path != ":memory:":
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Initializes the database schema if not already present."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                port INTEGER NOT NULL DEFAULT 443,
                scan_timestamp TEXT NOT NULL,
                overall_outcome TEXT NOT NULL,
                tls_version TEXT,
                cipher_suite TEXT,
                educational_score INTEGER,
                findings_count INTEGER DEFAULT 0,
                passed_count INTEGER DEFAULT 0,
                warning_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                is_completed INTEGER DEFAULT 1,
                error_message TEXT,
                details_json TEXT
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp 
            ON scan_history(scan_timestamp DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_hostname 
            ON scan_history(hostname);
        """)
        conn.commit()


def save_scan_record(db_path: str, scan_data: Dict[str, Any]) -> None:
    """Saves or updates a scan summary record using parameterized SQL."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scan_history (
                scan_id, hostname, ip_address, port, scan_timestamp,
                overall_outcome, tls_version, cipher_suite, educational_score,
                findings_count, passed_count, warning_count, failure_count,
                is_completed, error_message, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data.get("scan_id"),
            scan_data.get("hostname"),
            scan_data.get("ip_address"),
            scan_data.get("port", 443),
            scan_data.get("scan_timestamp"),
            scan_data.get("overall_outcome", "UNKNOWN"),
            scan_data.get("tls_version"),
            scan_data.get("cipher_suite"),
            scan_data.get("educational_score"),
            scan_data.get("findings_count", 0),
            scan_data.get("passed_count", 0),
            scan_data.get("warning_count", 0),
            scan_data.get("failure_count", 0),
            1 if scan_data.get("is_completed", True) else 0,
            scan_data.get("error_message"),
            json.dumps(scan_data.get("details", {}))
        ))
        conn.commit()


def get_recent_scans(
    db_path: str,
    limit: int = 50,
    search_query: Optional[str] = None,
    outcome_filter: Optional[str] = None,
    sort_by: str = "newest"
) -> List[Dict[str, Any]]:
    """
    Retrieves filtered and sorted scan history records with parameterized queries.
    """
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            query = """
                SELECT scan_id, hostname, ip_address, port, scan_timestamp,
                       overall_outcome, tls_version, cipher_suite, educational_score,
                       findings_count, passed_count, warning_count, failure_count,
                       is_completed, error_message
                FROM scan_history
                WHERE 1=1
            """
            params: List[Any] = []

            if search_query:
                query += " AND hostname LIKE ?"
                params.append(f"%{search_query.strip().lower()}%")

            if outcome_filter and outcome_filter.upper() not in ("ALL", ""):
                query += " AND overall_outcome = ?"
                params.append(outcome_filter.upper())

            # Sorting
            if sort_by == "oldest":
                query += " ORDER BY scan_timestamp ASC"
            elif sort_by == "score_desc":
                query += " ORDER BY educational_score DESC NULLS LAST"
            elif sort_by == "score_asc":
                query += " ORDER BY educational_score ASC NULLS LAST"
            elif sort_by == "hostname":
                query += " ORDER BY hostname ASC"
            else:  # newest default
                query += " ORDER BY scan_timestamp DESC"

            query += " LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []


def get_scan_by_id(db_path: str, scan_id: str) -> Optional[Dict[str, Any]]:
    """Fetches a specific scan record including its full details JSON."""
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scan_history WHERE scan_id = ?
            """, (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("details_json"):
                try:
                    data["details"] = json.loads(data["details_json"])
                except Exception:
                    data["details"] = {}
            return data
    except Exception:
        return None


def delete_scan_by_id(db_path: str, scan_id: str) -> bool:
    """Deletes a single scan record by ID."""
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_history WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0
    except Exception:
        return False


def clear_scan_history(db_path: str) -> bool:
    """Clears all scan history entries."""
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_history;")
            conn.commit()
            return True
    except Exception:
        return False


def get_history_statistics(db_path: str) -> Dict[str, Any]:
    """Computes aggregate analytics over the saved audit history."""
    stats = {
        "total_scans": 0,
        "secure_count": 0,
        "warning_count": 0,
        "insecure_count": 0,
        "failed_count": 0,
        "avg_score": None,
        "tls13_count": 0,
        "tls12_count": 0,
        "legacy_tls_count": 0
    }
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN overall_outcome = 'SECURE' THEN 1 ELSE 0 END) as secure_c,
                    SUM(CASE WHEN overall_outcome = 'WARNINGS' THEN 1 ELSE 0 END) as warn_c,
                    SUM(CASE WHEN overall_outcome = 'INSECURE' THEN 1 ELSE 0 END) as insec_c,
                    SUM(CASE WHEN overall_outcome = 'FAILED' THEN 1 ELSE 0 END) as fail_c,
                    AVG(educational_score) as avg_sc,
                    SUM(CASE WHEN tls_version = 'TLSv1.3' THEN 1 ELSE 0 END) as tls13_c,
                    SUM(CASE WHEN tls_version = 'TLSv1.2' THEN 1 ELSE 0 END) as tls12_c,
                    SUM(CASE WHEN tls_version IN ('TLSv1.0', 'TLSv1.1', 'SSLv3') THEN 1 ELSE 0 END) as legacy_c
                FROM scan_history
            """)
            row = cursor.fetchone()
            if row and row["total"]:
                stats["total_scans"] = row["total"] or 0
                stats["secure_count"] = row["secure_c"] or 0
                stats["warning_count"] = row["warn_c"] or 0
                stats["insecure_count"] = row["insec_c"] or 0
                stats["failed_count"] = row["fail_c"] or 0
                stats["avg_score"] = round(row["avg_sc"], 1) if row["avg_sc"] is not None else None
                stats["tls13_count"] = row["tls13_c"] or 0
                stats["tls12_count"] = row["tls12_c"] or 0
                stats["legacy_tls_count"] = row["legacy_c"] or 0
    except Exception:
        pass
    return stats
