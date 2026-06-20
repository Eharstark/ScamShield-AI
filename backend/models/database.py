"""
database.py

SQLite persistence layer for ScamShield AI.

Stores analysis history for SMS, URL, and Screenshot scans performed by the
detection engine. Provides simple, dependency-free functions intended to be
called directly from Flask route handlers.

Usage:
    from database import init_db, save_analysis, get_recent_scans, \
        get_total_scans, get_risk_distribution, get_scan_by_id, delete_scan

    init_db()  # call once at app startup (e.g. in app.py)
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

DB_NAME: str = "scamshield.db"


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """
    Context manager that yields a SQLite connection to the ScamShield database.

    The connection uses ``row_factory = sqlite3.Row`` so query results can be
    accessed like dictionaries, and ``PRAGMA foreign_keys`` is enabled for
    safety/future-proofing. The connection is always committed (on success)
    and closed automatically.

    Yields:
        sqlite3.Connection: An open connection to scamshield.db.

    Raises:
        sqlite3.Error: Re-raised after rolling back, if a database error
            occurs within the ``with`` block.
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """
    Initialize the ScamShield database.

    Creates ``scamshield.db`` (if it does not already exist) and ensures the
    ``analysis_history`` table is present. Safe to call multiple times (e.g.
    on every app startup) since it uses ``CREATE TABLE IF NOT EXISTS``.

    Raises:
        sqlite3.Error: If table creation fails for an unexpected reason.
    """
    try:
        with get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_type TEXT NOT NULL,
                    input_content TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    category TEXT,
                    explanation TEXT,
                    created_at TIMESTAMP NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_history_created_at
                ON analysis_history (created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_history_risk_level
                ON analysis_history (risk_level)
                """
            )
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to initialize database: {exc}") from exc


def save_analysis(
    analysis_type: str,
    input_content: str,
    risk_score: int,
    risk_level: str,
    category: Optional[str] = None,
    explanation: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Insert a new scan result into analysis_history.

    Args:
        analysis_type: Type of scan performed, e.g. "sms", "url", "screenshot".
        input_content: The raw input that was analyzed (message text, URL,
            or extracted screenshot text).
        risk_score: Numeric risk score, typically 0-100.
        risk_level: Risk classification, e.g. "low", "medium", "high".
        category: Optional category label, e.g. "Banking Scam", "UPI Scam".
        explanation: Optional human-readable explanation of the verdict.

    Returns:
        Dict[str, Any]: The newly created record, including its generated
        ``id`` and ``created_at`` timestamp.

    Raises:
        sqlite3.Error: If the insert fails.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO analysis_history (
                    analysis_type, input_content, risk_score,
                    risk_level, category, explanation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_type,
                    input_content,
                    risk_score,
                    risk_level,
                    category,
                    explanation,
                    created_at,
                ),
            )
            new_id = cursor.lastrowid
        return {
            "id": new_id,
            "analysis_type": analysis_type,
            "input_content": input_content,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "category": category,
            "explanation": explanation,
            "created_at": created_at,
        }
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to save analysis: {exc}") from exc


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve the most recent scan results, newest first.

    Args:
        limit: Maximum number of records to return. Defaults to 10.

    Returns:
        List[Dict[str, Any]]: A list of scan records as dictionaries.

    Raises:
        sqlite3.Error: If the query fails.
    """
    try:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, analysis_type, input_content, risk_score,
                       risk_level, category, explanation, created_at
                FROM analysis_history
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to fetch recent scans: {exc}") from exc


def get_total_scans() -> Dict[str, int]:
    """
    Get the total number of scans recorded.

    Returns:
        Dict[str, int]: e.g. ``{"total_scans": 150}``.

    Raises:
        sqlite3.Error: If the query fails.
    """
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total FROM analysis_history"
            ).fetchone()
        return {"total_scans": row["total"] if row else 0}
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to count scans: {exc}") from exc


def get_risk_distribution() -> Dict[str, int]:
    """
    Get a count of scans grouped by risk level.

    The result always includes "low", "medium", and "high" keys (defaulting
    to 0 if there are no matching records), so the frontend dashboard can
    render charts without missing-key errors. Any other risk_level values
    found in the data are included as additional keys.

    Returns:
        Dict[str, int]: e.g. ``{"low": 50, "medium": 70, "high": 30}``.

    Raises:
        sqlite3.Error: If the query fails.
    """
    distribution: Dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    try:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT risk_level, COUNT(*) AS count
                FROM analysis_history
                GROUP BY risk_level
                """
            ).fetchall()
        for row in rows:
            level = (row["risk_level"] or "unknown").lower()
            distribution[level] = row["count"]
        return distribution
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to compute risk distribution: {exc}") from exc


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single scan record by its id.

    Args:
        scan_id: The primary key of the scan to retrieve.

    Returns:
        Optional[Dict[str, Any]]: The matching record, or None if not found.

    Raises:
        sqlite3.Error: If the query fails.
    """
    try:
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, analysis_type, input_content, risk_score,
                       risk_level, category, explanation, created_at
                FROM analysis_history
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to fetch scan {scan_id}: {exc}") from exc


def delete_scan(scan_id: int) -> bool:
    """
    Delete a scan record by its id.

    Args:
        scan_id: The primary key of the scan to delete.

    Returns:
        bool: True if a record was deleted, False if no matching record
        existed.

    Raises:
        sqlite3.Error: If the delete fails.
    """
    try:
        with get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM analysis_history WHERE id = ?",
                (scan_id,),
            )
        return cursor.rowcount > 0
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to delete scan {scan_id}: {exc}") from exc


if __name__ == "__main__":
    # Allows running `python database.py` to manually initialize the DB.
    init_db()
    print(f"ScamShield database initialized at ./{DB_NAME}")
