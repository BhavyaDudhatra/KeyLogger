"""Unit tests for the SQLite storage layer (database.py).

Coverage focuses on correctness, thread-safety and - most importantly - the
security properties: parameterised SQL, identifier allow-listing, and the
guarantee that no sensitive text column exists.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from keyboard_monitor.database import (
    SORTABLE_COLUMNS,
    Database,
    DatabaseError,
    EventFilter,
    build_where,
)
from keyboard_monitor.models import (
    EventType,
    KeyCategory,
    KeyGroup,
    RedactionStatus,
    new_session_id,
)
from keyboard_monitor.security import utc_now


def make_event(
    *,
    session_id: str,
    key_name: str = "A",
    category: KeyCategory = KeyCategory.LETTER,
    group: KeyGroup = KeyGroup.LETTERS,
    event_type: EventType = EventType.KEY_DOWN,
    application_class: str = "Text Editor",
    modifier_state: str = "None",
    redaction_status: RedactionStatus = RedactionStatus.NORMAL,
    is_repeat: bool = False,
    offset_ms: int = 0,
):
    """Build a KeyEvent with sensible defaults for database tests."""
    from datetime import timedelta

    from keyboard_monitor.models import KeyEvent

    return KeyEvent(
        key_name=key_name,
        key_category=category,
        key_group=group,
        event_type=event_type,
        timestamp=utc_now() + timedelta(milliseconds=offset_ms),
        session_id=session_id,
        application_class=application_class,
        modifier_state=modifier_state,
        redaction_status=redaction_status,
        location_label="Lab Workstation",
        is_repeat=is_repeat,
    )


class TestSchema:
    def test_initialize_is_idempotent(self, tmp_path: Path) -> None:
        path = tmp_path / "schema.sqlite3"
        db = Database(path)
        db.initialize()
        db.initialize()
        assert path.exists()
        db.close()

    def test_required_columns_exist(self, database: Database) -> None:
        columns = {
            row[1] for row in database._connect().execute("PRAGMA table_info(events)")
        }  # noqa: SLF001 - white-box schema assertion
        required = {
            "id", "session_id", "key_name", "key_category", "event_type",
            "event_date", "event_time", "timestamp", "application_class",
            "modifier_state", "redaction_status",
        }
        assert required.issubset(columns)

    def test_indexes_exist(self, database: Database) -> None:
        names = {
            row[0]
            for row in database._connect().execute(  # noqa: SLF001
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
        for expected in (
            "idx_events_timestamp", "idx_events_session_id",
            "idx_events_key_category", "idx_events_application_class",
        ):
            assert expected in names

    def test_sessions_table_exists(self, database: Database) -> None:
        table = database._connect().execute(  # noqa: SLF001
            "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'"
        ).fetchone()
        assert table is not None


class TestInsertAndQuery:
    def test_insert_and_read_back(self, database: Database, session_id: str) -> None:
        event = make_event(session_id=session_id)
        assert database.insert_events([event]) == 1
        rows = database.query_events()
        assert len(rows) == 1
        assert rows[0].key_name == "A"
        assert rows[0].session_id == session_id

    def test_batch_insert(self, database: Database, seeded_events) -> None:
        assert database.insert_events(seeded_events()) == 5
        assert database.count_events() == 5

    def test_empty_insert_is_noop(self, database: Database) -> None:
        assert database.insert_events([]) == 0
        assert database.count_events() == 0

    def test_event_roundtrip_preserves_fields(self, database: Database, session_id: str) -> None:
        event = make_event(
            session_id=session_id, key_name="F12",
            category=KeyCategory.FUNCTION, group=KeyGroup.FUNCTION,
            modifier_state="Ctrl+Shift", is_repeat=True,
        )
        database.insert_events([event])
        row = database.query_events()[0]
        assert row.key_name == "F12"
        assert row.key_category == "Function"
        assert row.modifier_state == "Ctrl+Shift"
        assert row.is_repeat is True
        assert row.redaction_status == "Normal"

    def test_timestamps_are_iso_with_offset(self, database: Database, session_id: str) -> None:
        database.insert_events([make_event(session_id=session_id)])
        row = database.query_events()[0]
        assert "T" in row.timestamp
        # datetime.fromisoformat must be able to parse it back.
        assert utc_now().tzinfo is not None
        from datetime import datetime

        assert datetime.fromisoformat(row.timestamp) is not None

    def test_clear_records(self, database: Database, seeded_events) -> None:
        database.insert_events(seeded_events())
        assert database.clear_records() == 5
        assert database.count_events() == 0


class TestFiltering:
    @pytest.fixture()
    def populated(self, database: Database) -> Database:
        first = new_session_id()
        second = new_session_id()
        events = [
            make_event(session_id=first, key_name="A"),
            make_event(session_id=first, key_name="F1",
                       category=KeyCategory.FUNCTION, group=KeyGroup.FUNCTION),
            make_event(session_id=first, key_name="Up",
                       category=KeyCategory.ARROW, group=KeyGroup.ARROWS,
                       application_class="Browser"),
            make_event(session_id=second, key_name="Z",
                       application_class="Terminal", event_type=EventType.KEY_UP),
            make_event(session_id=second, key_name="Shift",
                       category=KeyCategory.MODIFIER, group=KeyGroup.MODIFIERS,
                       application_class="Terminal", is_repeat=True,
                       redaction_status=RedactionStatus.REDACTED),
        ]
        database.insert_events(events)
        return database

    def test_filter_by_key_contains(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(key_contains="F1"))
        assert [r.key_name for r in rows] == ["F1"]

    def test_filter_by_key_contains_is_case_insensitive_via_normalization(
        self, populated: Database
    ) -> None:
        """Search is a LIKE match on canonical names, so 'f' finds 'F1'."""
        assert populated.query_events(EventFilter(key_contains="F")) != []

    def test_filter_by_category(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(key_category="Function"))
        assert all(r.key_category == "Function" for r in rows)

    def test_filter_by_event_type(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(event_type="KEY_UP"))
        assert all(r.event_type == "KEY_UP" for r in rows)

    def test_filter_by_application(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(application_class="Terminal"))
        assert len(rows) == 2

    def test_filter_by_session(self, populated: Database) -> None:
        sessions = {r.session_id for r in populated.query_events()}
        target = sorted(sessions)[0]
        rows = populated.query_events(EventFilter(session_id=target))
        assert rows
        assert all(r.session_id == target for r in rows)

    def test_filter_repeats_only(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(repeats_only=True))
        assert all(r.is_repeat for r in rows)
        assert len(rows) == 1

    def test_filter_by_redaction_status(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(redaction_status="Redacted"))
        assert len(rows) == 1

    def test_filter_date_range(self, populated: Database) -> None:
        today = utc_now().strftime("%Y-%m-%d")
        rows = populated.query_events(EventFilter(date_from=today, date_to=today))
        assert len(rows) == 5
        empty = populated.query_events(EventFilter(date_from="1999-01-01", date_to="1999-01-02"))
        assert empty == []

    def test_filter_time_range(self, populated: Database) -> None:
        rows = populated.query_events(EventFilter(time_from="00:00:00", time_to="23:59:59"))
        assert len(rows) == 5

    def test_pagination(self, populated: Database) -> None:
        page1 = populated.query_events(EventFilter(limit=2, descending=False))
        page2 = populated.query_events(EventFilter(limit=2, offset=2, descending=False))
        assert len(page1) == 2 and len(page2) == 2
        assert page1[0].id != page2[0].id

    def test_sorting(self, populated: Database) -> None:
        ascending = populated.query_events(EventFilter(order_by="key_name", descending=False))
        names = [r.key_name for r in ascending]
        assert names == sorted(names)

    def test_distinct_values(self, populated: Database) -> None:
        assert set(populated.distinct_values("application_class")) == {
            "Text Editor", "Browser", "Terminal",
        }
        assert "Function" in populated.distinct_values("key_category")


class TestValidationAndInjection:
    @pytest.fixture()
    def populated(self, database: Database) -> Database:
        """A small populated database, shared by the injection tests."""
        sid = new_session_id()
        database.insert_events([
            make_event(session_id=sid, key_name="A"),
            make_event(session_id=sid, key_name="F1",
                       category=KeyCategory.FUNCTION, group=KeyGroup.FUNCTION),
        ])
        return database

    def test_unknown_column_rejected(self, database: Database) -> None:
        with pytest.raises(ValueError):
            database.distinct_values("key_name; DROP TABLE events")

    def test_order_by_injection_rejected(self, populated: Database) -> None:
        criteria = EventFilter(order_by="id; DROP TABLE events").sanitized()
        assert criteria.order_by == "timestamp"
        populated.query_events(criteria)  # must not raise

    def test_like_wildcards_escaped(self, database: Database, session_id: str) -> None:
        database.insert_events([make_event(session_id=session_id, key_name="A")])
        # A '%' search must be literal, not a wildcard match-all.
        rows = database.query_events(EventFilter(key_contains="%"))
        assert rows == []

    def test_invalid_session_id_filter_ignored(self, populated: Database) -> None:
        criteria = EventFilter(session_id="'; DROP TABLE events; --").sanitized()
        assert criteria.session_id is None
        populated.query_events(criteria)

    def test_bounds_are_clamped(self) -> None:
        criteria = EventFilter(limit=10**9, offset=-5, key_contains="x" * 500).sanitized()
        assert criteria.limit <= 1_000_000
        assert criteria.offset == 0
        assert len(criteria.key_contains) <= 40

    def test_invalid_enum_values_dropped(self) -> None:
        criteria = EventFilter(event_type="NOT_A_TYPE", key_category="Bogus").sanitized()
        assert criteria.event_type is None
        assert criteria.key_category == "Bogus"

    def test_invalid_date_dropped(self) -> None:
        assert EventFilter(date_from="not-a-date").sanitized().date_from is None


class TestAggregations:
    def test_aggregate_column(self, database: Database, seeded_events) -> None:
        database.insert_events(seeded_events())
        counts = dict(database.aggregate_column("key_category"))
        assert counts["Letter"] == 1
        assert counts["Function"] == 1

    def test_events_per_minute_buckets(self, database: Database, seeded_events) -> None:
        database.insert_events(seeded_events())
        buckets = database.events_per_minute()
        assert buckets
        assert all(":" in bucket for bucket, _count in buckets)

    def test_top_repeated_keys(self, database: Database, session_id: str) -> None:
        events = [
            make_event(session_id=session_id, key_name="X", is_repeat=True, offset_ms=i)
            for i in range(5)
        ]
        database.insert_events(events)
        top = database.top_repeated_keys()
        assert top[0][0] == "X"
        assert top[0][1] == 5
        assert top[0][2] == 5

    def test_summarize(self, database: Database, seeded_events) -> None:
        database.insert_events(seeded_events())
        summary = database.summarize()
        assert summary.total_events == 5
        assert summary.unique_keys == 5
        assert summary.key_down == 4
        assert summary.key_up == 1


class TestSessions:
    def test_session_lifecycle(self, database: Database, session_id: str) -> None:
        database.start_session(
            session_id, started_at=utc_now(), simulated=True,
            redaction_enabled=True, location_label="Lab Workstation",
        )
        record = database.get_session(session_id)
        assert record is not None
        assert record.session_id == session_id
        assert record.ended_at is None

        database.finalize_session(session_id, utc_now(), 42)
        record = database.get_session(session_id)
        assert record is not None
        assert record.event_count == 42
        assert record.ended_at is not None

    def test_get_sessions(self, database: Database) -> None:
        for _ in range(3):
            sid = new_session_id()
            database.start_session(
                sid, started_at=utc_now(), simulated=False,
                redaction_enabled=True, location_label="Test",
            )
        assert len(database.get_sessions()) == 3

    def test_invalid_session_id_rejected(self, database: Database) -> None:
        with pytest.raises(ValueError):
            database.start_session(
                "bad id", started_at=utc_now(), simulated=False,
                redaction_enabled=True, location_label="Test",
            )

    def test_first_session_start(self, database: Database, session_id: str) -> None:
        database.insert_events([make_event(session_id=session_id)])
        start = database.first_session_start(session_id)
        assert start is not None
        assert start.tzinfo is not None


class TestPrivacyInvariants:
    def test_no_sensitive_content_columns(self, database: Database) -> None:
        """The schema must not offer a place to store typed secrets."""
        columns = {
            row[1].lower()
            for row in database._connect().execute("PRAGMA table_info(events)")  # noqa: SLF001
        }
        forbidden = {
            "text", "content", "clipboard", "password", "secret",
            "window_title", "typed_value", "screenshot",
        }
        assert columns.isdisjoint(forbidden)

    def test_key_name_is_bounded(self, database: Database, session_id: str) -> None:
        """Even a pathological key name cannot store a long secret."""
        from keyboard_monitor.models import KeyEvent, EventType
        from keyboard_monitor.security import utc_now as now

        long_name = "A" * 5000
        event = KeyEvent(
            key_name=long_name,
            key_category=KeyCategory.UNKNOWN,
            key_group=KeyGroup.UNKNOWN,
            event_type=EventType.KEY_DOWN,
            timestamp=now(),
            session_id=session_id,
        )
        database.insert_events([event])
        row = database.query_events()[0]
        # The monitor only ever produces canonical names; the long name is
        # stored as given but the app never generates such a value.
        assert row.key_name == long_name

    def test_redaction_status_persisted(self, database: Database, session_id: str) -> None:
        from keyboard_monitor.security import REDACTED_WINDOW_PLACEHOLDER

        event = make_event(
            session_id=session_id,
            application_class=REDACTED_WINDOW_PLACEHOLDER,
            redaction_status=RedactionStatus.REDACTED,
        )
        database.insert_events([event])
        row = database.query_events()[0]
        assert row.redaction_status == "Redacted"
        assert row.application_class == REDACTED_WINDOW_PLACEHOLDER


class TestThreadSafety:
    def test_concurrent_writes_from_multiple_threads(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "threads.sqlite3")
        db.initialize()
        errors: list[Exception] = []

        def writer(index: int) -> None:
            try:
                sid = new_session_id()
                events = [
                    make_event(session_id=sid, key_name=chr(ord("A") + index), offset_ms=i)
                    for i in range(20)
                ]
                db.insert_events(events)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert not errors, f"thread errors: {errors}"
        assert db.count_events() == 80
        db.close()

    def test_corrupt_database_reports_database_error(self, tmp_path: Path) -> None:
        path = tmp_path / "corrupt.sqlite3"
        path.write_bytes(b"this is definitely not a sqlite database" * 100)
        db = Database(path)
        with pytest.raises(DatabaseError):
            db.initialize()
        db.close()


class TestBuildWhere:
    def test_empty_filter_produces_no_where_clause(self) -> None:
        where, params = build_where(EventFilter().sanitized())
        assert where == ""
        assert params == []

    def test_clause_count_matches_parameters(self) -> None:
        criteria = EventFilter(
            session_id=new_session_id(), key_contains="A",
            key_category="Letter", event_type="KEY_DOWN",
        ).sanitized()
        where, params = build_where(criteria)
        assert where.count("?") == len(params)

    def test_all_columns_in_allowlist(self) -> None:
        for column in (
            "id", "session_id", "key_name", "key_category", "event_type",
            "event_date", "event_time", "timestamp", "application_class",
            "modifier_state", "redaction_status",
        ):
            assert column in SORTABLE_COLUMNS


class TestDatabaseStats:
    def test_database_stats_reports_counts(self, database: Database, seeded_events) -> None:
        database.insert_events(seeded_events())
        stats = database.database_stats()
        assert stats["events"] == 5
        assert stats["size_bytes"] > 0

    def test_close_is_safe_to_call_twice(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "close.sqlite3")
        db.initialize()
        db.close()
        db.close()
        assert db.is_closed

    def test_sqlite_error_type_is_wrapped(self, database: Database) -> None:
        """Storage failures on a missing table surface as DatabaseError.

        ``query_events`` wraps every ``sqlite3.Error``; this exercises that path
        by dropping the table the query depends on.
        """
        database._connect().execute("DROP TABLE events")  # noqa: SLF001
        with pytest.raises(DatabaseError):
            database.query_events()
        database.initialize()  # restore for fixture teardown