"""SQLite persistence for keyboard event metadata.

Security notes
--------------
* **Every** user- or OS-supplied value reaches SQLite through a *parameterised*
  query.  The only identifiers ever interpolated are column names that have
  first been checked against an explicit allow-list (:data:`SORTABLE_COLUMNS`).
* The database stores event *metadata only*.  There is no column able to hold a
  password, token, clipboard payload or window text.
* Connections are per-thread (``threading.local``) which keeps the GUI thread
  free of cross-thread locking and lets the monitor worker write concurrently.
* ``PRAGMA journal_mode=WAL`` plus a busy timeout makes concurrent reads safe
  while the worker thread is writing.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Final, Iterable, Sequence

from .models import EventType, KeyEvent
from .security import is_valid_session_id, sanitize_label

LOGGER = logging.getLogger(__name__)

__all__ = [
    "Database",
    "DatabaseError",
    "DatabaseSummary",
    "EventFilter",
    "EventRow",
    "SessionRecord",
    "EXPORT_COLUMNS",
    "SORTABLE_COLUMNS",
    "build_where",
]

#: Columns the analyst may sort or filter on.  Anything else is rejected, which
#: removes SQL-injection risk from identifier interpolation.
SORTABLE_COLUMNS: Final[frozenset[str]] = frozenset({
    "id",
    "session_id",
    "key_name",
    "key_category",
    "event_type",
    "event_date",
    "event_time",
    "timestamp",
    "application_class",
    "modifier_state",
    "redaction_status",
    "location_label",
    "is_repeat",
})

#: Column layout shared by the GUI table and the Excel export.
EXPORT_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("id", "Sr. No."),
    ("key_name", "Key"),
    ("key_category", "Key Category"),
    ("event_date", "Date"),
    ("event_time", "Time"),
    ("timestamp", "Timestamp"),
    ("application_class", "Application/Window Classification"),
    ("modifier_state", "Modifier State"),
    ("event_type", "Event Type"),
    ("session_id", "Session ID"),
    ("redaction_status", "Redaction Status"),
    ("location_label", "Device / Location Label"),
    ("is_repeat", "Repeat Flag"),
)

_SCHEMA: Final[tuple[str, ...]] = (
    """
    CREATE TABLE IF NOT EXISTS events (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id         TEXT    NOT NULL,
        key_name           TEXT    NOT NULL,
        key_category       TEXT    NOT NULL,
        event_type         TEXT    NOT NULL,
        event_date         TEXT    NOT NULL,
        event_time         TEXT    NOT NULL,
        timestamp          TEXT    NOT NULL,
        epoch_ms           INTEGER NOT NULL,
        application_class  TEXT    NOT NULL,
        modifier_state     TEXT    NOT NULL,
        redaction_status   TEXT    NOT NULL,
        location_label     TEXT    NOT NULL DEFAULT '',
        is_repeat          INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id         TEXT PRIMARY KEY,
        started_at         TEXT NOT NULL,
        ended_at           TEXT,
        started_local      TEXT NOT NULL,
        ended_local        TEXT,
        event_count        INTEGER NOT NULL DEFAULT 0,
        simulated          INTEGER NOT NULL DEFAULT 0,
        redaction_enabled  INTEGER NOT NULL DEFAULT 1,
        location_label     TEXT NOT NULL DEFAULT '',
        analyst_note       TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_key_category ON events(key_category)",
    "CREATE INDEX IF NOT EXISTS idx_events_application_class ON events(application_class)",
    "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_session_timestamp ON events(session_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_date_time ON events(event_date, event_time)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at)",
)


class DatabaseError(RuntimeError):
    """Raised for unrecoverable storage problems (shown to the analyst)."""


@dataclass(slots=True)
class EventFilter:
    """Search / filter criteria for the event table.

    All values are treated as untrusted: they are bound as SQL parameters and
    additionally length-bounded before use.
    """

    session_id: str | None = None
    key_contains: str = ""
    key_category: str | None = None
    event_type: str | None = None
    application_class: str | None = None
    redaction_status: str | None = None
    date_from: str | None = None
    date_to: str | None = None
    time_from: str | None = None
    time_to: str | None = None
    repeats_only: bool = False
    order_by: str = "timestamp"
    descending: bool = True
    limit: int = 1000
    offset: int = 0

    def sanitized(self) -> "EventFilter":
        """Return a copy with untrusted fields bounded and identifiers checked."""
        limit = max(1, min(int(self.limit), 1_000_000))
        offset = max(0, min(int(self.offset), 10_000_000))
        order_by = self.order_by if self.order_by in SORTABLE_COLUMNS else "timestamp"
        session_id = self.session_id if is_valid_session_id(self.session_id) else None
        return EventFilter(
            session_id=session_id,
            key_contains=sanitize_label(self.key_contains, max_length=40),
            key_category=sanitize_label(self.key_category, max_length=40) or None,
            event_type=self._enum(EventType, self.event_type, 20),
            application_class=sanitize_label(self.application_class, max_length=60) or None,
            redaction_status=sanitize_label(self.redaction_status, max_length=20) or None,
            date_from=_valid_date(self.date_from),
            date_to=_valid_date(self.date_to),
            time_from=_valid_time(self.time_from),
            time_to=_valid_time(self.time_to),
            repeats_only=bool(self.repeats_only),
            order_by=order_by,
            descending=bool(self.descending),
            limit=limit,
            offset=offset,
        )

    @staticmethod
    def _enum(
        enum_cls: type[Enum], value: str | None, max_length: int
    ) -> str | None:
        if not value:
            return None
        candidate = sanitize_label(value, max_length=max_length)
        for member in enum_cls:
            if member.value.lower() == candidate.lower():
                return member.value
        return None


@dataclass(slots=True)
class EventRow:
    """A row of the ``events`` table, ready for display."""

    id: int
    session_id: str
    key_name: str
    key_category: str
    event_type: str
    event_date: str
    event_time: str
    timestamp: str
    application_class: str
    modifier_state: str
    redaction_status: str
    location_label: str
    is_repeat: bool

    @classmethod
    def from_tuple(cls, values: Sequence[Any]) -> "EventRow":
        return cls(
            id=int(values[0]),
            session_id=str(values[1]),
            key_name=str(values[2]),
            key_category=str(values[3]),
            event_type=str(values[4]),
            event_date=str(values[5]),
            event_time=str(values[6]),
            timestamp=str(values[7]),
            application_class=str(values[8]),
            modifier_state=str(values[9]),
            redaction_status=str(values[10]),
            location_label=str(values[11]),
            is_repeat=bool(values[12]),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "Sr. No.": self.id,
            "Key": self.key_name,
            "Key Category": self.key_category,
            "Date": self.event_date,
            "Time": self.event_time,
            "Timestamp": self.timestamp,
            "Application/Window Classification": self.application_class,
            "Modifier State": self.modifier_state,
            "Event Type": self.event_type,
            "Session ID": self.session_id,
            "Redaction Status": self.redaction_status,
            "Device / Location Label": self.location_label,
            "Repeat Flag": "REPEAT" if self.is_repeat else "",
        }


@dataclass(slots=True)
class SessionRecord:
    """Row of the ``sessions`` table."""

    session_id: str
    started_at: str
    ended_at: str | None
    started_local: str
    ended_local: str | None
    event_count: int
    simulated: bool
    redaction_enabled: bool
    location_label: str
    analyst_note: str = ""

    @classmethod
    def from_tuple(cls, values: Sequence[Any]) -> "SessionRecord":
        return cls(
            session_id=str(values[0]),
            started_at=str(values[1]),
            ended_at=str(values[2]) if values[2] else None,
            started_local=str(values[3]),
            ended_local=str(values[4]) if values[4] else None,
            event_count=int(values[5]),
            simulated=bool(values[6]),
            redaction_enabled=bool(values[7]),
            location_label=str(values[8]),
            analyst_note=str(values[9]),
        )


def _valid_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return None


def _valid_time(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).strftime("%H:%M:%S")
        except ValueError:
            continue
    return None


def build_where(criteria: EventFilter) -> tuple[str, list[Any]]:
    """Build a parameterised ``WHERE`` clause for a sanitised filter.

    Only fixed column names are interpolated; every value is bound as a
    parameter, and ``LIKE`` wildcards in the search box are escaped.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if criteria.session_id:
        clauses.append("session_id = ?")
        params.append(criteria.session_id)
    if criteria.key_contains:
        clauses.append("key_name LIKE ? ESCAPE '\\'")
        # Escape LIKE wildcards so a search string cannot act as a pattern.
        needle = (
            criteria.key_contains.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        params.append(f"%{needle}%")
    for column, value in (
        ("key_category", criteria.key_category),
        ("event_type", criteria.event_type),
        ("application_class", criteria.application_class),
        ("redaction_status", criteria.redaction_status),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    if criteria.date_from:
        clauses.append("event_date >= ?")
        params.append(criteria.date_from)
    if criteria.date_to:
        clauses.append("event_date <= ?")
        params.append(criteria.date_to)
    if criteria.time_from:
        clauses.append("event_time >= ?")
        params.append(criteria.time_from)
    if criteria.time_to:
        clauses.append("event_time <= ?")
        params.append(criteria.time_to)
    if criteria.repeats_only:
        clauses.append("is_repeat = 1")
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


class Database:
    """Thread-safe SQLite wrapper for keyboard event metadata."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._local = threading.local()
        self._closed = False
        self._lock = threading.Lock()

    # -- connection management -------------------------------------------- #
    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _connect(self) -> sqlite3.Connection:
        """Return this thread's connection, creating it on first use."""
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            return connection
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                str(self._path),
                timeout=10.0,
                isolation_level=None,  # explicit transaction control
            )
            connection.row_factory = None
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=10000")
            self._local.connection = connection
        except (sqlite3.Error, OSError) as exc:
            raise DatabaseError(f"Could not open the event database: {exc}") from exc
        return connection

    def initialize(self) -> None:
        """Create tables and indexes if they do not exist yet."""
        connection = self._connect()
        try:
            for statement in _SCHEMA:
                connection.execute(statement)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not initialise the event database: {exc}") from exc

    def close(self) -> None:
        """Close this thread's connection and mark the database closed."""
        self._closed = True
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:  # pragma: no cover - best effort
                LOGGER.debug("Error while closing SQLite connection.", exc_info=True)
            self._local.connection = None

    def close_all(self) -> int:
        """Close this thread's connection (called on shutdown).

        Worker threads own - and close - their own connections before the GUI
        reaches this point, so there is nothing left to reclaim for them.
        """
        closed = 0
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            try:
                connection.close()
                closed = 1
            except sqlite3.Error:  # pragma: no cover - best effort
                pass
            self._local.connection = None
        self._closed = True
        return closed

    # -- writes ------------------------------------------------------------ #
    def insert_events(self, events: Iterable[KeyEvent]) -> int:
        """Batch-insert events inside a single transaction.

        Returns the number of rows written.  Failures roll the whole batch back
        so the database never contains half of a logical batch.
        """
        rows = [
            (
                event.session_id,
                event.key_name,
                event.key_category.value,
                event.event_type.value,
                event.event_date,
                event.event_time,
                event.iso_timestamp,
                int(event.timestamp.timestamp() * 1000),
                event.application_class,
                event.modifier_state,
                event.redaction_status.value,
                event.location_label,
                1 if event.is_repeat else 0,
            )
            for event in events
        ]
        if not rows:
            return 0

        connection = self._connect()
        sql = (
            "INSERT INTO events (session_id, key_name, key_category, event_type, "
            "event_date, event_time, timestamp, epoch_ms, application_class, "
            "modifier_state, redaction_status, location_label, is_repeat) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        try:
            with self._lock:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.executemany(sql, rows)
                except sqlite3.Error:
                    connection.execute("ROLLBACK")
                    raise
                connection.execute("COMMIT")
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not write keyboard events: {exc}") from exc
        return len(rows)

    def start_session(
        self,
        session_id: str,
        *,
        started_at: datetime,
        simulated: bool,
        redaction_enabled: bool,
        location_label: str,
        analyst_note: str = "",
    ) -> None:
        """Record the beginning of a monitoring session."""
        if not is_valid_session_id(session_id):
            raise ValueError("Refusing to record a session with an invalid session id.")
        connection = self._connect()
        try:
            connection.execute(
                "INSERT OR REPLACE INTO sessions (session_id, started_at, started_local, "
                "event_count, simulated, redaction_enabled, location_label, analyst_note) "
                "VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
                (
                    session_id,
                    started_at.isoformat(timespec="milliseconds"),
                    started_at.strftime("%Y-%m-%d %H:%M:%S"),
                    1 if simulated else 0,
                    1 if redaction_enabled else 0,
                    sanitize_label(location_label, max_length=120),
                    sanitize_label(analyst_note, max_length=200),
                ),
            )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not record the session start: {exc}") from exc

    def finalize_session(self, session_id: str, ended_at: datetime, event_count: int) -> None:
        """Record the end of a monitoring session and its final event count."""
        if not is_valid_session_id(session_id):
            raise ValueError("Refusing to finalize a session with an invalid session id.")
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE sessions SET ended_at = ?, ended_local = ?, event_count = ? "
                "WHERE session_id = ?",
                (
                    ended_at.isoformat(timespec="milliseconds"),
                    ended_at.strftime("%Y-%m-%d %H:%M:%S"),
                    max(0, int(event_count)),
                    session_id,
                ),
            )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not record the session end: {exc}") from exc

    def set_session_note(self, session_id: str, note: str) -> None:
        if not is_valid_session_id(session_id):
            raise ValueError("Invalid session id.")
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE sessions SET analyst_note = ? WHERE session_id = ?",
                (sanitize_label(note, max_length=200), session_id),
            )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not update the session note: {exc}") from exc

    def clear_records(self, *, keep_sessions: bool = True) -> int:
        """Delete every stored event.

        Used by *Clear Records*.  Returns the number of deleted rows.
        """
        connection = self._connect()
        try:
            with self._lock:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    cursor = connection.execute("DELETE FROM events")
                    deleted = int(cursor.rowcount or 0)
                    if not keep_sessions:
                        connection.execute("DELETE FROM sessions")
                    else:
                        connection.execute("UPDATE sessions SET event_count = 0")
                except sqlite3.Error:
                    connection.execute("ROLLBACK")
                    raise
                connection.execute("COMMIT")
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not clear stored records: {exc}") from exc
        return deleted

    def vacuum(self) -> None:
        """Compact the database file after a large deletion."""
        connection = self._connect()
        try:
            connection.execute("VACUUM")
        except sqlite3.Error as exc:
            LOGGER.warning("VACUUM failed (not fatal): %s", exc)

    # -- reads -------------------------------------------------------------- #
    def query_events(self, criteria: EventFilter | None = None) -> list[EventRow]:
        """Return filtered event rows, newest first by default."""
        criteria = (criteria or EventFilter()).sanitized()
        where, params = build_where(criteria)
        order = criteria.order_by if criteria.order_by in SORTABLE_COLUMNS else "timestamp"
        direction = "DESC" if criteria.descending else "ASC"
        sql = (
            "SELECT id, session_id, key_name, key_category, event_type, event_date, "
            "event_time, timestamp, application_class, modifier_state, redaction_status, "
            f"location_label, is_repeat FROM events{where} "
            f"ORDER BY {order} {direction}, id {direction} LIMIT ? OFFSET ?"
        )
        # LIMIT/OFFSET are integers produced by EventFilter.sanitized().
        connection = self._connect()
        try:
            cursor = connection.execute(sql, (*params, criteria.limit, criteria.offset))
            return [EventRow.from_tuple(row) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not read keyboard events: {exc}") from exc

    def count_events(self, criteria: EventFilter | None = None) -> int:
        """Return the number of events matching the filter (ignores limit)."""
        criteria = (criteria or EventFilter()).sanitized()
        where, params = build_where(criteria)
        connection = self._connect()
        try:
            cursor = connection.execute(f"SELECT COUNT(*) FROM events{where}", params)
            row = cursor.fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not count keyboard events: {exc}") from exc

    def fetch_for_export(self, criteria: EventFilter | None = None) -> list[EventRow]:
        """Return rows for an export, ordered chronologically."""
        export_criteria = (criteria or EventFilter()).sanitized()
        export_criteria.descending = False
        export_criteria.order_by = "id"
        export_criteria.limit = 1_000_000
        export_criteria.offset = 0
        return self.query_events(export_criteria)

    def distinct_values(self, column: str) -> list[str]:
        """Return the distinct values of an allow-listed column (for filters)."""
        if column not in SORTABLE_COLUMNS:
            raise ValueError(f"Refusing to build a filter for column {column!r}.")
        connection = self._connect()
        try:
            cursor = connection.execute(
                f"SELECT DISTINCT {column} FROM events WHERE {column} <> '' "
                f"ORDER BY {column} ASC"
            )
            return [str(row[0]) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not read filter values: {exc}") from exc

    def get_sessions(self, *, limit: int = 500) -> list[SessionRecord]:
        """Return recent sessions, newest first."""
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT session_id, started_at, ended_at, started_local, ended_local, "
                "event_count, simulated, redaction_enabled, location_label, analyst_note "
                "FROM sessions ORDER BY started_at DESC LIMIT ?",
                (max(1, min(int(limit), 10_000)),),
            )
            return [SessionRecord.from_tuple(row) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not read sessions: {exc}") from exc

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Return one session record, or ``None`` when it does not exist."""
        if not is_valid_session_id(session_id):
            return None
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT session_id, started_at, ended_at, started_local, ended_local, "
                "event_count, simulated, redaction_enabled, location_label, analyst_note "
                "FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not read the session record: {exc}") from exc
        return SessionRecord.from_tuple(row) if row else None

    def first_session_start(self, session_id: str) -> datetime | None:
        """Return the first event timestamp of a session, if any."""
        if not is_valid_session_id(session_id):
            return None
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT timestamp FROM events WHERE session_id = ? ORDER BY epoch_ms ASC LIMIT 1",
                (session_id,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not read session start: {exc}") from exc
        if not row:
            return None
        return _parse_timestamp(str(row[0]))

    def aggregate_column(self, column: str, criteria: EventFilter | None = None) -> list[tuple[str, int]]:
        """Return ``(value, count)`` pairs for an allow-listed column."""
        if column not in SORTABLE_COLUMNS:
            raise ValueError(f"Refusing to aggregate column {column!r}.")
        criteria = (criteria or EventFilter()).sanitized()
        where, params = build_where(criteria)
        connection = self._connect()
        try:
            cursor = connection.execute(
                f"SELECT {column} AS value, COUNT(*) AS total FROM events{where} "
                f"GROUP BY value ORDER BY total DESC, value ASC",
                params,
            )
            return [(str(row[0]), int(row[1])) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not aggregate {column}: {exc}") from exc

    def events_per_minute(self, criteria: EventFilter | None = None) -> list[tuple[str, int]]:
        """Return ``(HH:MM, event_count)`` buckets for the timeline chart."""
        criteria = (criteria or EventFilter()).sanitized()
        where, params = build_where(criteria)
        connection = self._connect()
        try:
            cursor = connection.execute(
                f"SELECT substr(event_time, 1, 5) AS bucket, COUNT(*) AS total "
                f"FROM events{where} GROUP BY bucket ORDER BY bucket ASC",
                params,
            )
            return [(str(row[0]), int(row[1])) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not build the timeline: {exc}") from exc

    def top_repeated_keys(self, limit: int = 10) -> list[tuple[str, int, int]]:
        """Return ``(key_name, total_events, repeat_events)`` for top keys."""
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT key_name, COUNT(*) AS total, SUM(is_repeat) AS repeats "
                "FROM events GROUP BY key_name ORDER BY total DESC, key_name ASC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            )
            return [(str(r[0]), int(r[1]), int(r[2] or 0)) for r in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not read repeated-key statistics: {exc}") from exc

    def database_stats(self) -> dict[str, Any]:
        """Return size / row-count information for the status area."""
        connection = self._connect()
        stats: dict[str, Any] = {"path": str(self._path), "events": 0, "sessions": 0,
                                 "size_bytes": 0}
        try:
            stats["events"] = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            stats["sessions"] = int(connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
        except sqlite3.Error as exc:
            LOGGER.warning("Could not read database statistics: %s", exc)
        try:
            if self._path.exists():
                stats["size_bytes"] = self._path.stat().st_size
        except OSError:  # pragma: no cover - permissions
            pass
        return stats

    def summarize(self, criteria: EventFilter | None = None) -> "DatabaseSummary":
        """Compute a :class:`DatabaseSummary` for the given filter."""
        criteria = (criteria or EventFilter()).sanitized()
        where, params = build_where(criteria)
        connection = self._connect()
        summary = DatabaseSummary()
        try:
            cursor = connection.execute(
                "SELECT COUNT(*), "
                "SUM(CASE WHEN event_type = 'KEY_DOWN' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN event_type = 'KEY_UP' THEN 1 ELSE 0 END), "
                "COUNT(DISTINCT key_name), "
                "SUM(is_repeat), "
                "SUM(CASE WHEN redaction_status <> 'Normal' THEN 1 ELSE 0 END), "
                "MIN(timestamp), MAX(timestamp) "
                f"FROM events{where}",
                params,
            )
            row = cursor.fetchone()
            if row:
                summary.total_events = int(row[0] or 0)
                summary.key_down = int(row[1] or 0)
                summary.key_up = int(row[2] or 0)
                summary.unique_keys = int(row[3] or 0)
                summary.repeat_events = int(row[4] or 0)
                summary.redacted_events = int(row[5] or 0)
                summary.first_timestamp = str(row[6] or "")
                summary.last_timestamp = str(row[7] or "")
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not summarize events: {exc}") from exc
        summary.categories = self.aggregate_column("key_category", criteria)
        summary.applications = self.aggregate_column("application_class", criteria)
        return summary


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class DatabaseSummary:
    """Lightweight aggregate used by the dashboard (cheap to recompute)."""

    total_events: int = 0
    key_down: int = 0
    key_up: int = 0
    unique_keys: int = 0
    repeat_events: int = 0
    redacted_events: int = 0
    first_timestamp: str = ""
    last_timestamp: str = ""
    categories: list[tuple[str, int]] = field(default_factory=list)
    applications: list[tuple[str, int]] = field(default_factory=list)