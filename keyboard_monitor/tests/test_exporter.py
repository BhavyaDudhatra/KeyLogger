"""Unit tests for the Excel exporter (exporter.py).

The exporter is the highest-risk module from a data-leak perspective, so the
tests verify both workbook structure and privacy invariants.
"""

from __future__ import annotations

import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from openpyxl import load_workbook

from keyboard_monitor.config import DEFAULT_SENSITIVE_PATTERNS
from keyboard_monitor.database import Database, EventFilter
from keyboard_monitor.exporter import (
    EVENTS_SHEET,
    EVENT_HEADERS,
    SUMMARY_HEADERS,
    SUMMARY_SHEET,
    ExportError,
    export_to_excel,
)
from keyboard_monitor.models import (
    EventType,
    KeyCategory,
    KeyEvent,
    KeyGroup,
    RedactionStatus,
    new_session_id,
)
from keyboard_monitor.security import (
    REDACTED_WINDOW_PLACEHOLDER,
    SECURITY_GUARANTEES,
    strip_sensitive_literals,
    utc_now,
)


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
) -> KeyEvent:
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


@pytest.fixture()
def populated(database: Database) -> tuple[Database, str]:
    """Database with one session covering several key categories."""
    sid = new_session_id()
    started = utc_now() - timedelta(minutes=2)
    database.start_session(
        sid, started_at=started, simulated=True,
        redaction_enabled=True, location_label="Lab Workstation",
    )
    events = [
        make_event(session_id=sid, key_name="A", offset_ms=0),
        make_event(session_id=sid, key_name="Shift",
                   category=KeyCategory.MODIFIER, group=KeyGroup.MODIFIERS, offset_ms=100),
        make_event(session_id=sid, key_name="F5",
                   category=KeyCategory.FUNCTION, group=KeyGroup.FUNCTION, offset_ms=200),
        make_event(session_id=sid, key_name="Up",
                   category=KeyCategory.ARROW, group=KeyGroup.ARROWS, offset_ms=300),
        make_event(session_id=sid, key_name="Enter",
                   category=KeyCategory.NAVIGATION, group=KeyGroup.NAVIGATION,
                   event_type=EventType.KEY_UP, offset_ms=400),
        make_event(session_id=sid, key_name="A",
                   application_class=REDACTED_WINDOW_PLACEHOLDER,
                   redaction_status=RedactionStatus.REDACTED, offset_ms=500),
    ]
    database.insert_events(events)
    database.finalize_session(sid, utc_now(), len(events))
    return database, sid


class TestWorkbookStructure:
    def test_creates_both_worksheets(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        target = tmp_path / "out.xlsx"
        result = export_to_excel(database, target, criteria=EventFilter(session_id=sid))
        workbook = load_workbook(result.path)
        assert workbook.sheetnames == [EVENTS_SHEET, SUMMARY_SHEET]

    def test_sheet_names_exact(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "names.xlsx",
                                 criteria=EventFilter(session_id=sid))
        workbook = load_workbook(result.path)
        assert workbook[EVENTS_SHEET].title == "Keyboard Events"
        assert workbook[SUMMARY_SHEET].title == "Session Summary"

    def test_event_headers_match_specification(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "headers.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        headers = [cell.value for cell in sheet[1]]
        assert headers == list(EVENT_HEADERS)
        for required in ("Sr. No.", "Key", "Key Category", "Date", "Time",
                         "Timestamp", "Modifier State", "Event Type",
                         "Session ID", "Redaction Status"):
            assert required in headers

    def test_summary_headers(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "summary.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[SUMMARY_SHEET]
        headers = [cell.value for cell in sheet[1]]
        assert headers == list(SUMMARY_HEADERS)
        for required in ("Session ID", "Start Time", "End Time", "Total Events",
                         "Unique Keys", "Event Categories", "Applications Observed",
                         "Export Time", "Redaction Mode"):
            assert required in headers

    def test_freeze_header_row(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "freeze.xlsx",
                                 criteria=EventFilter(session_id=sid))
        workbook = load_workbook(result.path)
        assert workbook[EVENTS_SHEET].freeze_panes == "A2"
        assert workbook[SUMMARY_SHEET].freeze_panes == "A2"

    def test_autofilter_enabled(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "filter.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        assert sheet.auto_filter.ref is not None
        assert sheet.auto_filter.ref.startswith("A1")

    def test_column_widths_autofit(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "widths.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        widths = [dim.width for dim in sheet.column_dimensions.values()]
        assert widths
        assert all(width is not None and width > 0 for width in widths)
        # Widths are clamped, so none should be absurdly wide.
        assert max(widths) <= 46

    def test_header_styling(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "style.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        assert sheet["A1"].font.bold is True


class TestDataFidelity:
    def test_all_rows_exported(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "rows.xlsx",
                                 criteria=EventFilter(session_id=sid))
        assert result.event_rows == 6
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        assert sheet.max_row == 7  # header + 6 events

    def test_filters_are_honoured(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(
            database, tmp_path / "filtered.xlsx",
            criteria=EventFilter(session_id=sid, key_category="Function"),
        )
        assert result.event_rows == 1
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        assert sheet["C2"].value == "Function"

    def test_summary_reflects_session(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "sum.xlsx",
                                 criteria=EventFilter(session_id=sid),
                                 redaction_enabled=True)
        sheet = load_workbook(result.path)[SUMMARY_SHEET]
        headers = [cell.value for cell in sheet[1]]
        row = [cell.value for cell in sheet[2]]
        values = dict(zip(headers, row))
        assert values["Session ID"] == sid
        assert values["Total Events"] == 6
        assert values["Unique Keys"] == 5
        assert "Redaction Mode" in values
        assert "ENABLED" in values["Redaction Mode"]

    def test_export_time_recorded(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "time.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[SUMMARY_SHEET]
        assert result.exported_at is not None
        assert sheet.cell(row=2, column=8).value is not None

    def test_redaction_mode_disabled_recorded(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "off.xlsx",
                                 criteria=EventFilter(session_id=sid),
                                 redaction_enabled=False)
        sheet = load_workbook(result.path)[SUMMARY_SHEET]
        assert "DISABLED" in sheet.cell(row=2, column=9).value

    def test_empty_database_export(self, database: Database, tmp_path: Path) -> None:
        """An empty database still yields a valid, openable workbook."""
        result = export_to_excel(database, tmp_path / "empty.xlsx")
        assert result.event_rows == 0
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        assert sheet.max_row == 1  # header only
        summary = load_workbook(result.path)[SUMMARY_SHEET]
        assert summary.cell(row=2, column=1).value == "ALL RECORDS"

    def test_export_result_metadata(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "meta.xlsx",
                                 criteria=EventFilter(session_id=sid))
        assert result.path.name == "meta.xlsx"
        assert result.session_rows == 1
        assert result.redaction_enabled is True
        assert result.warnings == []


class TestPrivacy:
    def test_no_typed_secrets_in_workbook(self, populated, tmp_path: Path) -> None:
        """The workbook contains key names only, never assembled text."""
        database, sid = populated
        result = export_to_excel(database, tmp_path / "privacy.xlsx",
                                 criteria=EventFilter(session_id=sid))
        workbook = load_workbook(result.path)
        for sheet in workbook.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for value in row:
                    if isinstance(value, str):
                        # Nothing should look like a sentence the user typed.
                        assert "password" not in value.lower()

    def test_redaction_placeholder_preserved(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "redact.xlsx",
                                 criteria=EventFilter(session_id=sid))
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        values = [cell.value for row in sheet.iter_rows() for cell in row]
        assert REDACTED_WINDOW_PLACEHOLDER in values

    def test_sensitive_literals_scrubbed(self, populated, tmp_path: Path) -> None:
        """Defence-in-depth: patterns are stripped even from coarse values."""
        database, sid = populated
        result = export_to_excel(
            database, tmp_path / "scrub.xlsx",
            criteria=EventFilter(session_id=sid),
            sensitive_patterns=DEFAULT_SENSITIVE_PATTERNS,
        )
        sheet = load_workbook(result.path)[EVENTS_SHEET]
        for row in sheet.iter_rows(values_only=True):
            for value in row:
                if isinstance(value, str):
                    assert "bank" not in value.lower()
                    assert "login" not in value.lower()

    def test_strip_sensitive_literals_function(self) -> None:
        text = "my bank login details"
        scrubbed = strip_sensitive_literals(text, ["bank", "login"])
        assert "bank" not in scrubbed.lower()
        assert "login" not in scrubbed.lower()
        assert REDACTED_WINDOW_PLACEHOLDER in scrubbed

    def test_security_notice_appended(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "notice.xlsx",
                                 criteria=EventFilter(session_id=sid),
                                 notice=SECURITY_GUARANTEES)
        sheet = load_workbook(result.path)[SUMMARY_SHEET]
        all_text = " ".join(
            str(cell.value) for row in sheet.iter_rows() for cell in row if cell.value
        )
        assert "SECURITY NOTICE" in all_text
        assert "never starts automatically" in all_text

    def test_no_clipboard_or_screenshot_columns(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "cols.xlsx",
                                 criteria=EventFilter(session_id=sid))
        headers = [cell.value for cell in load_workbook(result.path)[EVENTS_SHEET][1]]
        for forbidden in ("clipboard", "screenshot", "password", "text content"):
            assert not any(forbidden in str(header).lower() for header in headers)


class TestErrorHandling:
    def test_non_xlsx_extension_rejected(self, populated, tmp_path: Path) -> None:
        database, _sid = populated
        with pytest.raises(ExportError, match="xlsx"):
            export_to_excel(database, tmp_path / "report.csv")

    def test_empty_destination_rejected(self, populated) -> None:
        database, _sid = populated
        with pytest.raises(ExportError):
            export_to_excel(database, "")

    def test_directory_destination_rejected(self, populated, tmp_path: Path) -> None:
        database, _sid = populated
        with pytest.raises(ExportError):
            export_to_excel(database, tmp_path)

    def test_locked_file_reports_permission_error(self, populated, tmp_path: Path) -> None:
        """A file open in Excel surfaces a friendly message, not a traceback."""
        database, sid = populated
        target = tmp_path / "locked.xlsx"
        export_to_excel(database, target, criteria=EventFilter(session_id=sid))
        with zipfile.ZipFile(target, "a") as archive:  # keeps the file in use
            archive.writestr("lock.txt", "held open")
            with pytest.raises(ExportError):
                export_to_excel(
                    database, target, criteria=EventFilter(session_id=sid)
                )

    def test_database_failure_reported(self, tmp_path: Path) -> None:
        """An uninitialized database produces ExportError, not a raw error."""
        database = Database(tmp_path / "missing.sqlite3")
        with pytest.raises(ExportError):
            export_to_excel(database, tmp_path / "fail.xlsx")
        database.close()


class TestFileHandling:
    def test_no_temp_directories_left_behind(self, populated, tmp_path: Path) -> None:
        """The staging directory is removed even after a successful export."""
        database, sid = populated
        export_to_excel(database, tmp_path / "clean.xlsx",
                        criteria=EventFilter(session_id=sid))
        leftovers = [p for p in tmp_path.iterdir() if p.is_dir()]
        assert leftovers == []

    def test_overwrites_existing_file(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        target = tmp_path / "twice.xlsx"
        export_to_excel(database, target, criteria=EventFilter(session_id=sid))
        result = export_to_excel(database, target, criteria=EventFilter(session_id=sid))
        assert result.event_rows == 6
        assert target.exists()

    def test_nested_directory_created(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        target = tmp_path / "nested" / "deeper" / "report.xlsx"
        result = export_to_excel(database, target, criteria=EventFilter(session_id=sid))
        assert result.path.exists()

    def test_file_is_valid_xlsx_zip(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(database, tmp_path / "valid.xlsx",
                                 criteria=EventFilter(session_id=sid))
        assert zipfile.is_zipfile(result.path)


class TestRowLimit:
    def test_max_rows_truncates_with_warning(self, populated, tmp_path: Path) -> None:
        database, sid = populated
        result = export_to_excel(
            database, tmp_path / "limited.xlsx",
            criteria=EventFilter(session_id=sid), max_rows=2,
        )
        assert result.event_rows == 2
        assert result.warnings
        assert "2" in result.warnings[0]