"""Excel (.xlsx) export of keyboard event metadata.

Produces a workbook with two worksheets:

``Keyboard Events``
    One row per recorded event, with a frozen header row, Excel autofilters,
    auto-adjusted column widths and red highlighting for redacted rows.

``Session Summary``
    One row per monitoring session with the fields required for a defensive
    report, followed by the security notice that accompanies the export.

Security notes
--------------
* The workbook is staged inside a private (0700) temporary directory created in
  the destination folder and then moved into place with :func:`os.replace`, so
  a failed export never leaves a half-written report behind and never exposes a
  readable partial file to other local users.
* Every exported string is passed through
  :func:`~keyboard_monitor.security.strip_sensitive_literals` as defence in
  depth.  The stored data is already coarse metadata, but this guarantees that
  a future change cannot leak raw secrets into a spreadsheet.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Final, Sequence

import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .config import REDACTED_WINDOW_PLACEHOLDER
from .database import EXPORT_COLUMNS, Database, EventFilter, EventRow, SessionRecord
from .security import safe_export_path, secure_temp_dir, strip_sensitive_literals, utc_now

LOGGER = logging.getLogger(__name__)

__all__ = ["ExportError", "ExportResult", "export_to_excel", "EVENTS_SHEET", "SUMMARY_SHEET"]

EVENTS_SHEET: Final[str] = "Keyboard Events"
SUMMARY_SHEET: Final[str] = "Session Summary"

EVENT_HEADERS: Final[tuple[str, ...]] = tuple(title for _column, title in EXPORT_COLUMNS)

SUMMARY_HEADERS: Final[tuple[str, ...]] = (
    "Session ID",
    "Start Time",
    "End Time",
    "Total Events",
    "Unique Keys",
    "Event Categories",
    "Applications Observed",
    "Export Time",
    "Redaction Mode",
)

#: Character bounds for auto-fitted column widths.
_MIN_WIDTH: Final[int] = 10
_MAX_WIDTH: Final[int] = 46

_HEADER_FILL: Final[PatternFill] = PatternFill("solid", fgColor="1F3864")
_HEADER_FONT: Final[Font] = Font(bold=True, color="FFFFFF", size=11)
_REDACTED_FILL: Final[PatternFill] = PatternFill("solid", fgColor="FFF2CC")
_TITLE_FONT: Final[Font] = Font(bold=True, size=13, color="1F3864")
_LABEL_FONT: Final[Font] = Font(bold=True)


class ExportError(RuntimeError):
    """Raised when the workbook could not be produced (shown to the analyst)."""


@dataclass(slots=True)
class ExportResult:
    """Outcome of a successful export."""

    path: Path
    event_rows: int
    session_rows: int
    exported_at: datetime
    redaction_enabled: bool
    warnings: list[str] = field(default_factory=list)


def _pair_counts(pairs: Sequence[tuple[str, int]], *, limit: int = 12) -> str:
    """Format ``[(value, count), ...]`` as ``"Letter (61%), Number (12%)"``."""
    if not pairs:
        return "None recorded"
    shown = pairs[:limit]
    text = ", ".join(f"{value} ({count})" for value, count in shown)
    if len(pairs) > limit:
        text += f", +{len(pairs) - limit} more"
    return text


def _events_frame(rows: Sequence[EventRow], patterns: Sequence[str]) -> pd.DataFrame:
    """Build the ``Keyboard Events`` DataFrame with the redaction pass applied."""
    records: list[dict[str, object]] = []
    for row in rows:
        record = row.as_dict()
        records.append({
            header: (
                strip_sensitive_literals(value, patterns)
                if isinstance(value, str)
                else value
            )
            for header, value in record.items()
        })
    frame = pd.DataFrame(records, columns=list(EVENT_HEADERS))
    return frame


def _summary_frame(
    sessions: Sequence[SessionRecord],
    *,
    total_events: int,
    unique_keys: int,
    categories: Sequence[tuple[str, int]],
    applications: Sequence[tuple[str, int]],
    redaction_enabled: bool,
    fallback_range: tuple[str, str] | None,
    patterns: Sequence[str],
) -> pd.DataFrame:
    """Build the ``Session Summary`` DataFrame (one row per session)."""
    mode = (
        f"ENABLED - {REDACTED_WINDOW_PLACEHOLDER} applied to sensitive windows"
        if redaction_enabled
        else "DISABLED - analyst opted out; classifications stored as resolved"
    )
    exported_at = utc_now().strftime("%Y-%m-%d %H:%M:%S %z")

    records: list[dict[str, object]] = []
    for session in sessions:
        records.append({
            "Session ID": session.session_id,
            "Start Time": session.started_local or session.started_at,
            "End Time": session.ended_local or session.ended_at or "Session still running",
            "Total Events": session.event_count,
            "Unique Keys": unique_keys,
            "Event Categories": _pair_counts(categories),
            "Applications Observed": _pair_counts(applications),
            "Export Time": exported_at,
            "Redaction Mode": mode,
        })

    if not records:
        start, end = fallback_range or ("—", "—")
        records.append({
            "Session ID": "ALL RECORDS",
            "Start Time": start,
            "End Time": end,
            "Total Events": total_events,
            "Unique Keys": unique_keys,
            "Event Categories": _pair_counts(categories),
            "Applications Observed": _pair_counts(applications),
            "Export Time": exported_at,
            "Redaction Mode": mode,
        })

    frame = pd.DataFrame(records, columns=list(SUMMARY_HEADERS))
    for column in frame.columns:
        if frame[column].dtype == object:
            frame[column] = frame[column].map(
                lambda value: strip_sensitive_literals(value, patterns)
                if isinstance(value, str) else value
            )
    return frame


def _auto_fit(worksheet, *, header: int = 1) -> None:
    """Set column widths from the widest rendered cell, within bounds."""
    widths: dict[int, int] = {}
    for row in worksheet.iter_rows(min_row=header):
        for cell in row:
            value = cell.value
            if value is None:
                continue
            text = value if isinstance(value, str) else str(value)
            # Long prose cells (e.g. the security notice) should not blow up a
            # column width, so cap the measurement at a sensible window.
            sample = text if len(text) <= 80 else text[:77] + "..."
            widths[cell.column] = max(widths.get(cell.column, 0), len(sample) + 2)
    for column_index, width in widths.items():
        worksheet.column_dimensions[get_column_letter(column_index)].width = min(
            max(width, _MIN_WIDTH), _MAX_WIDTH
        )


def _style_events_sheet(worksheet) -> None:
    worksheet.freeze_panes = "A2"
    for cell in worksheet[1]:
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    worksheet.row_dimensions[1].height = 30
    worksheet.auto_filter.ref = worksheet.dimensions

    # Emphasise the redaction-status column and mark redacted rows.
    headers = [cell.value for cell in worksheet[1]]
    if "Redaction Status" in headers:
        status_index = headers.index("Redaction Status") + 1
        for row_index in range(2, worksheet.max_row + 1):
            cell = worksheet.cell(row=row_index, column=status_index)
            if isinstance(cell.value, str) and cell.value != "Normal":
                for column_index in range(1, len(headers) + 1):
                    worksheet.cell(row=row_index, column=column_index).fill = _REDACTED_FILL

    _auto_fit(worksheet)


def _style_summary_sheet(worksheet, notice: Sequence[str]) -> None:
    for cell in worksheet[1]:
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    worksheet.row_dimensions[1].height = 30
    worksheet.freeze_panes = "A2"
    worksheet.auto_filter.ref = worksheet.dimensions

    # Section 1: session summary table (already written by pandas).
    last_row = worksheet.max_row
    for row_index in range(2, last_row + 1):
        for column_index in range(1, worksheet.max_column + 1):
            worksheet.cell(row=row_index, column=column_index).alignment = Alignment(
                vertical="top", wrap_text=column_index in (6, 7)
            )
    _auto_fit(worksheet)

    # Section 2: accompanying security notice (overflows into empty columns).
    notice_start = last_row + 2
    worksheet.cell(row=notice_start, column=1, value="SECURITY NOTICE").font = _TITLE_FONT
    for offset, line in enumerate(notice, start=1):
        cell = worksheet.cell(row=notice_start + offset, column=1, value=line)
        cell.alignment = Alignment(vertical="top", wrap_text=False)


def export_to_excel(
    database: Database,
    destination: Path | str,
    *,
    criteria: EventFilter | None = None,
    redaction_enabled: bool = True,
    sensitive_patterns: Sequence[str] = (),
    notice: Sequence[str] = (),
    max_rows: int = 200_000,
) -> ExportResult:
    """Export filtered keyboard events to an ``.xlsx`` workbook.

    Parameters
    ----------
    database:
        Open :class:`~keyboard_monitor.database.Database`.
    destination:
        Analyst-chosen path; must end in ``.xlsx``.
    criteria:
        Which rows to export.  Defaults to every stored event.
    redaction_enabled:
        Recorded verbatim in the Session Summary sheet so a report always states
        whether the privacy mode was active.
    sensitive_patterns:
        Extra substrings scrubbed from every exported string.
    notice:
        Security-notice lines appended to the Session Summary sheet.

    Raises
    ------
    ExportError
        For any user-facing failure (locked file, unwritable directory, missing
        optional dependency, and so on).
    """
    target = _validate_destination(destination)
    criteria = (criteria or EventFilter()).sanitized()
    exported_at = utc_now()

    try:
        rows = database.fetch_for_export(criteria)
    except Exception as exc:
        raise ExportError(f"Could not read the records to export: {exc}") from exc

    warnings: list[str] = []
    if len(rows) > max_rows:
        warnings.append(
            f"Only the first {max_rows:,} matching rows were exported "
            f"({len(rows):,} matched the filter)."
        )
        rows = rows[:max_rows]

    summary = _safe_summary(database, criteria)
    sessions = _sessions_for(database, criteria)
    fallback_range = (summary.first_timestamp or "—", summary.last_timestamp or "—")

    events_frame = _events_frame(rows, sensitive_patterns)
    summary_frame = _summary_frame(
        sessions,
        total_events=summary.total_events,
        unique_keys=summary.unique_keys,
        categories=summary.categories,
        applications=summary.applications,
        redaction_enabled=redaction_enabled,
        fallback_range=fallback_range,
        patterns=sensitive_patterns,
    )

    _write_workbook(target, events_frame, summary_frame, notice)

    LOGGER.info(
        "Exported %d event row(s) and %d session row(s) to %s",
        len(rows), len(summary_frame), target,
    )
    return ExportResult(
        path=target,
        event_rows=len(rows),
        session_rows=len(summary_frame),
        exported_at=exported_at,
        redaction_enabled=redaction_enabled,
        warnings=warnings,
    )


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #
def _validate_destination(destination: Path | str) -> Path:
    try:
        target = safe_export_path(destination)
    except ValueError as exc:
        raise ExportError(str(exc)) from exc

    parent = target.parent if str(target.parent) else Path.cwd()
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ExportError(
            f"The folder {parent} could not be created or written to ({exc})."
        ) from exc
    if not os.access(parent, os.W_OK):
        raise ExportError(f"You do not have permission to write to {parent}.")
    if target.exists() and not os.access(target, os.W_OK):
        raise ExportError(
            f"{target.name} cannot be overwritten - close it in Excel and try again."
        )
    return target.absolute()


def _safe_summary(database: Database, criteria: EventFilter):
    try:
        return database.summarize(criteria)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("Summary unavailable for export: %s", exc)
        from .database import DatabaseSummary

        return DatabaseSummary()


def _sessions_for(database: Database, criteria: EventFilter) -> list[SessionRecord]:
    """Return the session records represented in the export, chronologically.

    The session ids are derived from the *filtered* event set, so exporting a
    single session only ever produces a one-row summary.
    """
    try:
        pairs = database.aggregate_column("session_id", criteria)
        if not pairs:
            return []
        records = database.get_sessions(limit=5000)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("Session list unavailable for export: %s", exc)
        return []

    by_id = {record.session_id: record for record in records}
    selected = [by_id[session_id] for session_id, _count in pairs if session_id in by_id]
    selected.sort(key=lambda record: record.started_at)
    return selected


def _write_workbook(
    target: Path,
    events_frame: pd.DataFrame,
    summary_frame: pd.DataFrame,
    notice: Sequence[str],
) -> None:
    """Write both worksheets into a staged workbook and move it into place."""
    try:
        with secure_temp_dir(parent=target.parent) as staging:
            staged_path = staging / target.name
            with pd.ExcelWriter(staged_path, engine="openpyxl") as writer:
                events_frame.to_excel(
                    writer, sheet_name=EVENTS_SHEET, index=False, startrow=0
                )
                summary_frame.to_excel(
                    writer, sheet_name=SUMMARY_SHEET, index=False, startrow=0
                )
                _style_events_sheet(writer.sheets[EVENTS_SHEET])
                _style_summary_sheet(writer.sheets[SUMMARY_SHEET], notice)
            os.replace(staged_path, target)
    except PermissionError as exc:
        raise ExportError(
            f"{target.name} is locked or read-only. Close it in Excel and try again."
        ) from exc
    except (OSError, ValueError) as exc:
        raise ExportError(f"The Excel file could not be written: {exc}") from exc
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise ExportError(
            "The Excel export dependencies (pandas / openpyxl) are not installed. "
            "Run: pip install pandas openpyxl"
        ) from exc
    except Exception as exc:  # pragma: no cover - unexpected openpyxl failure
        raise ExportError(f"Unexpected error while writing the Excel file: {exc}") from exc