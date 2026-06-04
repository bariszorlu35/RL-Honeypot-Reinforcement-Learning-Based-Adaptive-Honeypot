"""SQLite database layer for RL-Honeypot.

All DB logic is centralised here. A threading.Lock serialises writes so
concurrent honeypot threads do not corrupt the database.
"""

import sqlite3
import threading
from typing import List, Optional

import config

_db_lock = threading.Lock()


def init_db() -> None:
    """Create sessions and commands tables if they do not exist."""
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id                TEXT PRIMARY KEY,
                mode              TEXT,
                attacker_profile  TEXT,
                start_time        REAL,
                duration          REAL,
                command_count     INTEGER,
                unique_categories INTEGER,
                behavior_class    TEXT,
                engagement_score  REAL,
                total_reward      REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT,
                timestamp    REAL,
                command      TEXT,
                category     TEXT,
                action_taken TEXT,
                reward       REAL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        conn.commit()


def log_session(
    mode: str,
    session_id: str,
    attacker_profile: str,
    start_time: float,
    duration: float,
    command_count: int,
    unique_categories: int,
    behavior_class: str,
    engagement_score: float,
    total_reward: float,
) -> None:
    """Insert (or replace) one completed session record."""
    with _db_lock:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id, mode, attacker_profile, start_time, duration,
                    command_count, unique_categories, behavior_class,
                    engagement_score, total_reward,
                ),
            )
            conn.commit()


def log_command(
    session_id: str,
    command: str,
    category: str,
    action_taken: str,
    reward: float,
    timestamp: float,
) -> None:
    """Insert one command record."""
    with _db_lock:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                """INSERT INTO commands
                   (session_id, timestamp, command, category, action_taken, reward)
                   VALUES (?,?,?,?,?,?)""",
                (session_id, timestamp, command, category, action_taken, reward),
            )
            conn.commit()


def get_all_sessions(mode: Optional[str] = None) -> List[dict]:
    """Return all sessions as a list of dicts, optionally filtered by mode."""
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if mode:
            cur.execute(
                "SELECT * FROM sessions WHERE mode = ? ORDER BY start_time", (mode,)
            )
        else:
            cur.execute("SELECT * FROM sessions ORDER BY start_time")
        return [dict(row) for row in cur.fetchall()]


def get_session_commands(session_id: str) -> List[dict]:
    """Return all commands for a given session_id, ordered by timestamp."""
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        )
        return [dict(row) for row in cur.fetchall()]


def get_recent_commands(limit: int = 200) -> List[dict]:
    """Return the most recent command records with session context."""
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                commands.id,
                commands.session_id,
                commands.timestamp,
                commands.command,
                commands.category,
                commands.action_taken,
                commands.reward,
                sessions.mode,
                sessions.attacker_profile,
                sessions.behavior_class
            FROM commands
            LEFT JOIN sessions ON commands.session_id = sessions.id
            ORDER BY commands.timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]


def clear_db() -> None:
    """Delete all records from both tables (used for fresh demo runs)."""
    with _db_lock:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute("DELETE FROM commands")
            conn.execute("DELETE FROM sessions")
            conn.commit()
