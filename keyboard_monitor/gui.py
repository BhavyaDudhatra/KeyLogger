"""PySide6 desktop GUI for the authorized keyboard event monitor.

Design goals
------------
* Professional cybersecurity-console look: dark slate palette, monospace log
  table, colour-coded status (green = logging, red = stopped, orange = warning,
  blue/grey = informational).
* Responsive while recording: the capture thread never touches Qt widgets; the
  GUI only reacts to signals and a low-frequency refresh timer.
* Consent-first: *Start Logging* stays disabled until the analyst has explicitly
  acknowledged the consent notice, and nothing is ever captured automatically.

Security notes
--------------
* The window is a normal top-level window - no tray icon, no hide-on-close, no
  background/daemon behaviour.
* No password, token or typed-text widget exists anywhere in this file; the
  table shows key names and coarse classifications only.
* Every user-supplied string is bounded before it reaches SQLite or an export.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Final, Sequence

from PySide6.QtCore import (
    QAbstractTableModel,
    QDate,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QRectF,
    QSize,
    Qt,
    QTime,
    QTimer,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFont, QFontMetrics, QKeySequence, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTableView,
    QTabWidget,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)

from .analytics import DashboardStats, compute_dashboard
from .config import APP_TITLE, APP_VERSION, AppConfig, ConfigStore, data_dir
from .database import EXPORT_COLUMNS, Database, DatabaseError, EventFilter
from .event_monitor import EventMonitor, MonitoringError
from .exporter import ExportError, export_to_excel
from .models import EventType, KeyCategory, KeyEvent, RedactionStatus
from .security import (
    NOT_IMPLEMENTED_BY_DESIGN,
    REDACTED_WINDOW_PLACEHOLDER,
    SECURITY_GUARANTEES,
    sanitize_label,
)

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #
COLOUR_ACTIVE: Final[QColor] = QColor("#22c55e")      # green  - logging
COLOUR_STOPPED: Final[QColor] = QColor("#ef4444")     # red    - stopped
COLOUR_WARNING: Final[QColor] = QColor("#f59e0b")     # orange - warning
COLOUR_INFO: Final[QColor] = QColor("#38bdf8")        # blue   - informational
COLOUR_NEUTRAL: Final[QColor] = QColor("#94a3b8")     # grey   - neutral

COLOUR_BG: Final[str] = "#0f172a"
COLOUR_PANEL: Final[str] = "#1e293b"
COLOUR_BORDER: Final[str] = "#334155"
COLOUR_TEXT: Final[str] = "#e2e8f0"
COLOUR_MUTED: Final[str] = "#94a3b8"

CONSENT_TEXT: Final[str] = (
    "AUTHORIZED USE ONLY - Record keyboard event metadata on this device only "
    "with the knowledge and consent of the person using it. Monitoring without "
    "consent is unlawful. Redaction mode is ON by default: sensitive windows are "
    "recorded only as "
    f"{REDACTED_WINDOW_PLACEHOLDER} and no typed text, passwords, tokens or "
    "clipboard contents are ever captured."
)


def _stylesheet() -> str:
    """Global dark cybersecurity-console stylesheet."""
    return f"""
    QWidget {{
        background-color: {COLOUR_BG};
        color: {COLOUR_TEXT};
        font-size: 12px;
    }}
    QMainWindow::separator {{ background: {COLOUR_BORDER}; width: 1px; height: 1px; }}
    QGroupBox {{
        border: 1px solid {COLOUR_BORDER};
        border-radius: 6px;
        margin-top: 14px;
        padding-top: 10px;
        background-color: {COLOUR_PANEL};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 4px;
        color: {COLOUR_MUTED};
        font-weight: bold;
    }}
    QLabel {{ background: transparent; }}
    QLabel#Banner {{
        background-color: #3f2d12;
        border: 1px solid {COLOUR_WARNING.name()};
        border-radius: 6px;
        color: #fde68a;
        padding: 8px;
        font-weight: bold;
    }}
    QLabel#Value {{
        background-color: {COLOUR_PANEL};
        border: 1px solid {COLOUR_BORDER};
        border-radius: 4px;
        padding: 6px;
        font-family: "Consolas", "Menlo", monospace;
    }}
    QLabel#Heading {{
        color: {COLOUR_MUTED};
        font-size: 10px;
        font-weight: bold;
        letter-spacing: 1px;
    }}
    QPushButton {{
        background-color: {COLOUR_PANEL};
        border: 1px solid {COLOUR_BORDER};
        border-radius: 5px;
        padding: 7px 14px;
        font-weight: bold;
    }}
    QPushButton:hover:!disabled {{ border-color: {COLOUR_INFO.name()}; }}
    QPushButton:pressed:!disabled {{ background-color: {COLOUR_BORDER}; }}
    QPushButton:disabled {{ color: #475569; border-color: #1e293b; }}
    QPushButton#StartButton {{ border: 1px solid {COLOUR_ACTIVE.name()}; color: {COLOUR_ACTIVE.name()}; }}
    QPushButton#StopButton {{ border: 1px solid {COLOUR_STOPPED.name()}; color: {COLOUR_STOPPED.name()}; }}
    QLineEdit, QComboBox, QSpinBox, QDateEdit, QTimeEdit {{
        background-color: {COLOUR_PANEL};
        border: 1px solid {COLOUR_BORDER};
        border-radius: 4px;
        padding: 4px 6px;
        selection-background-color: {COLOUR_INFO.name()};
    }}
    QComboBox::drop-down {{ border: none; width: 18px; }}
    QComboBox QAbstractItemView {{
        background-color: {COLOUR_PANEL};
        border: 1px solid {COLOUR_BORDER};
        selection-background-color: {COLOUR_INFO.name()};
    }}
    QTableView {{
        background-color: {COLOUR_PANEL};
        alternate-background-color: #172033;
        gridline-color: {COLOUR_BORDER};
        border: 1px solid {COLOUR_BORDER};
        border-radius: 6px;
        selection-background-color: #1d4ed8;
        font-family: "Consolas", "Menlo", monospace;
    }}
    QHeaderView::section {{
        background-color: #263449;
        color: {COLOUR_TEXT};
        border: none;
        border-right: 1px solid {COLOUR_BORDER};
        border-bottom: 1px solid {COLOUR_BORDER};
        padding: 6px;
        font-weight: bold;
    }}
    QTableView QTableCornerButton::section {{ background-color: #263449; border: none; }}
    QTabWidget::pane {{ border: 1px solid {COLOUR_BORDER}; border-radius: 6px; top: -1px; }}
    QTabBar::tab {{
        background: {COLOUR_PANEL};
        color: {COLOUR_MUTED};
        padding: 8px 16px;
        border: 1px solid {COLOUR_BORDER};
        border-bottom: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
    }}
    QTabBar::tab:selected {{ color: {COLOUR_TEXT}; background: #263449; }}
    QTabBar::tab:hover:!selected {{ color: {COLOUR_TEXT}; }}
    QPlainTextEdit {{
        background-color: {COLOUR_PANEL};
        border: 1px solid {COLOUR_BORDER};
        border-radius: 4px;
        font-family: "Consolas", "Menlo", monospace;
    }}
    QProgressBar {{
        border: 1px solid {COLOUR_BORDER};
        border-radius: 4px;
        background-color: {COLOUR_PANEL};
        text-align: center;
        max-height: 18px;
    }}
    QProgressBar::chunk {{ background-color: {COLOUR_INFO.name()}; border-radius: 3px; }}
    QStatusBar {{ background-color: {COLOUR_PANEL}; color: {COLOUR_MUTED}; }}
    QStatusBar::item {{ border: none; }}
    QScrollBar:vertical {{ background: {COLOUR_BG}; width: 12px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {COLOUR_BORDER}; border-radius: 6px; min-height: 24px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar:horizontal {{ background: {COLOUR_BG}; height: 12px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: {COLOUR_BORDER}; border-radius: 6px; min-width: 24px; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{
        width: 16px; height: 16px;
        border: 1px solid {COLOUR_BORDER};
        border-radius: 3px;
        background-color: {COLOUR_PANEL};
    }}
    QCheckBox::indicator:checked {{ background-color: {COLOUR_INFO.name()}; border-color: {COLOUR_INFO.name()}; }}
    """


def _format_duration(seconds: float) -> str:
    """Render ``seconds`` as ``HH:MM:SS``."""
    total = int(max(0.0, seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class StatusStrip(QWidget):
    """The required status block: status, event count, start time, duration."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.status_label = QLabel("Status: STOPPED")
        self.status_label.setObjectName("Value")
        self.status_label.setMinimumWidth(190)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.events_label = QLabel("Events Recorded: 0")
        self.events_label.setObjectName("Value")
        self.events_label.setMinimumWidth(170)
        self.events_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.started_label = QLabel("Session Started: -")
        self.started_label.setObjectName("Value")
        self.started_label.setMinimumWidth(180)
        self.started_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.duration_label = QLabel("Session Duration: -")
        self.duration_label.setObjectName("Value")
        self.duration_label.setMinimumWidth(180)
        self.duration_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        for widget in (self.status_label, self.events_label,
                       self.started_label, self.duration_label):
            layout.addWidget(widget)
        layout.addStretch(1)

        self._color_status(COLOUR_STOPPED)

    # -- helpers ------------------------------------------------------------ #
    def _color_status(self, colour: QColor) -> None:
        self.status_label.setStyleSheet(
            f"color: {colour.name()}; font-weight: bold; letter-spacing: 1px;"
        )

    def set_active(self, active: bool) -> None:
        """Switch between the ``● LOGGING`` and ``STOPPED`` presentations."""
        if active:
            self.status_label.setText("● LOGGING")
            self._color_status(COLOUR_ACTIVE)
        else:
            self.status_label.setText("Status: STOPPED")
            self._color_status(COLOUR_STOPPED)

    def set_event_count(self, count: int) -> None:
        self.events_label.setText(f"Events Recorded: {count:,}")

    def set_started(self, moment: datetime | None) -> None:
        self.started_label.setText(
            f"Session Started: {moment.strftime('%H:%M:%S')}" if moment else "Session Started: -"
        )

    def set_duration(self, seconds: float | None) -> None:
        self.duration_label.setText(
            f"Session Duration: {_format_duration(seconds)}" if seconds is not None
            else "Session Duration: -"
        )


class EventTableModel(QAbstractTableModel):
    """Table model over a list of :class:`~keyboard_monitor.database.EventRow`.

    Only key names, coarse classifications and timing metadata are shown.  There
    is deliberately no column capable of displaying captured text content.
    """

    HEADERS: Final[tuple[str, ...]] = tuple(title for _column, title in EXPORT_COLUMNS)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rows: list[Any] = []

    # -- Qt model API ------------------------------------------------------- #
    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation,  # noqa: N802
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else None
        return section + 1

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        values = row.as_dict()
        header = self.HEADERS[index.column()]

        if role == Qt.ItemDataRole.DisplayRole:
            value = values.get(header)
            if header == "Repeat Flag":
                return "REPEAT" if value else ""
            if value is None:
                return ""
            return str(value)

        if role == Qt.ItemDataRole.ForegroundRole:
            return self._row_colour(row)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if header in {"Sr. No.", "Date", "Time"}:
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ToolTipRole:
            # Tooltip repeats metadata only - never window text.
            return (
                f"Key: {row.key_name}\nCategory: {row.key_category}\n"
                f"Event: {row.event_type}\nModifiers: {row.modifier_state}\n"
                f"Application class: {row.application_class}\n"
                f"Redaction: {row.redaction_status}\nSession: {row.session_id}"
            )

        if role == Qt.ItemDataRole.FontRole and header in {"Key", "Key Category"}:
            font = QFont()
            font.setBold(True)
            return font

        return None

    # -- helpers ------------------------------------------------------------ #
    @staticmethod
    def _row_colour(row: Any) -> QColor | None:
        if row.redaction_status != RedactionStatus.NORMAL.value:
            return COLOUR_WARNING
        if row.application_class == REDACTED_WINDOW_PLACEHOLDER:
            return COLOUR_WARNING
        if row.key_category == KeyCategory.MODIFIER.value:
            return COLOUR_INFO
        if row.key_category == KeyCategory.UNKNOWN.value:
            return COLOUR_NEUTRAL
        if row.is_repeat:
            return COLOUR_NEUTRAL
        return None

    # -- data management ---------------------------------------------------- #
    def set_rows(self, rows: Sequence[Any]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> list[Any]:
        return list(self._rows)

    def row_at(self, index: int) -> Any | None:
        if 0 <= index < len(self._rows):
            return self._rows[index]
        return None


class SimpleBarChart(QWidget):
    """A small dependency-free bar chart painted with ``QPainter``.

    The project deliberately ships no plotting library: the dashboard only
    needs labelled bars for the per-minute timeline and the key-category mix,
    and hand-drawing them keeps the install light and the rendering predictable
    on every platform Qt supports.
    """

    ORIENTATION_HORIZONTAL: Final[str] = "horizontal"

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        orientation: str = "vertical",
        empty_text: str = "No data to display.",
    ) -> None:
        super().__init__(parent)
        self._orientation = orientation
        self._empty_text = empty_text
        self._series: list[tuple[str, float]] = []
        self._colour = COLOUR_INFO
        self.setMinimumHeight(170)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

    # -- data ---------------------------------------------------------------- #
    def set_series(
        self,
        series: Sequence[tuple[str, float]],
        *,
        colour: QColor | None = None,
    ) -> None:
        """Replace the plotted data and schedule a repaint."""
        self._series = [(str(name), float(value)) for name, value in series]
        if colour is not None:
            self._colour = colour
        self.update()

    def clear(self) -> None:
        """Drop the plotted data, keeping the current colour."""
        self._series = []
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt naming
        return QSize(360, 190)

    # -- painting ------------------------------------------------------------ #
    def paintEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.fillRect(self.rect(), QColor(COLOUR_PANEL))
            painter.setPen(QPen(QColor(COLOUR_BORDER), 1))
            painter.drawRect(self.rect().adjusted(0, 0, -1, -1))

            if not self._series:
                self._paint_empty(painter)
                return
            if self._orientation == self.ORIENTATION_HORIZONTAL:
                self._paint_horizontal(painter)
            else:
                self._paint_vertical(painter)
        finally:
            painter.end()

    def _paint_empty(self, painter: QPainter) -> None:
        painter.setPen(QColor(COLOUR_MUTED))
        painter.drawText(
            self.rect(),
            Qt.AlignmentFlag.AlignCenter,
            self._empty_text,
        )

    def _bar_colour(self, index: int) -> QColor:
        """Bars fade along the palette so long series stay readable."""
        base = self._colour
        shade = 1.0 - (0.45 * index / max(len(self._series), 1))
        return QColor(
            int(base.red() * shade),
            int(base.green() * shade),
            int(base.blue() * shade),
        )

    def _paint_vertical(self, painter: QPainter) -> None:
        metrics = QFontMetrics(self.font())
        left, right, top, bottom = 46, 10, 12, 22
        plot = QRectF(
            left,
            top,
            max(self.width() - left - right, 1.0),
            max(self.height() - top - bottom, 1.0),
        )
        peak = max((value for _name, value in self._series), default=0.0) or 1.0

        painter.setPen(QPen(QColor(COLOUR_BORDER), 1))
        painter.drawLine(int(plot.left()), int(plot.bottom()),
                         int(plot.right()), int(plot.bottom()))
        painter.setPen(QColor(COLOUR_MUTED))
        painter.drawText(
            QRectF(0, plot.top() - 2, left - 6, metrics.height()),
            int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            f"{peak:,.0f}",
        )

        slot = plot.width() / len(self._series)
        bar_width = max(slot - 3.0, 1.5)
        label_every = max(1, len(self._series) // 8)
        for index, (name, value) in enumerate(self._series):
            height = (value / peak) * plot.height()
            x = plot.left() + (index * slot) + (slot - bar_width) / 2
            rect = QRectF(x, plot.bottom() - height, bar_width, height)
            painter.fillRect(rect, self._bar_colour(index))
            if index % label_every == 0:
                painter.setPen(QColor(COLOUR_MUTED))
                short = name[-5:] if len(name) > 5 else name
                painter.drawText(
                    QRectF(plot.left() + index * slot, plot.bottom() + 2, slot, 16),
                    int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop),
                    metrics.elidedText(short, Qt.TextElideMode.ElideRight, int(slot) + 4),
                )

    def _paint_horizontal(self, painter: QPainter) -> None:
        metrics = QFontMetrics(self.font())
        left, right, top, bottom = 118, 44, 10, 10
        plot = QRectF(
            left,
            top,
            max(self.width() - left - right, 1.0),
            max(self.height() - top - bottom, 1.0),
        )
        peak = max((value for _name, value in self._series), default=0.0) or 1.0
        rows = min(len(self._series), 8)
        row_height = plot.height() / rows

        for index, (name, value) in enumerate(self._series[:rows]):
            centre = plot.top() + (index * row_height) + (row_height / 2)
            bar_height = max(row_height - 6.0, 3.0)
            width = (value / peak) * plot.width()

            painter.setPen(QColor(COLOUR_TEXT))
            painter.drawText(
                QRectF(0, centre - (row_height / 2), left - 8, row_height),
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                metrics.elidedText(name, Qt.TextElideMode.ElideRight, left - 10),
            )
            painter.fillRect(
                QRectF(plot.left(), centre - (bar_height / 2), max(width, 1.0), bar_height),
                self._bar_colour(index),
            )
            painter.setPen(QColor(COLOUR_MUTED))
            painter.drawText(
                QRectF(plot.left() + width + 4, centre - (row_height / 2), right, row_height),
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                f"{value:,.0f}",
            )


class DashboardPanel(QWidget):
    """Statistics dashboard: headline counters plus category/app breakdowns."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(10)

        # -- headline counters --------------------------------------------- #
        counters = QGridLayout()
        counters.setHorizontalSpacing(8)
        counters.setVerticalSpacing(6)
        self._counters: dict[str, QLabel] = {}
        counter_specs = (
            ("total_events", "TOTAL EVENTS"),
            ("events_per_minute", "EVENTS / MINUTE"),
            ("unique_keys", "UNIQUE KEYS"),
            ("session_duration", "SESSION DURATION"),
            ("key_down", "KEY_DOWN"),
            ("key_up", "KEY_UP"),
            ("modifier_keys", "MODIFIER KEYS"),
            ("function_keys", "FUNCTION KEYS"),
            ("navigation_keys", "NAVIGATION KEYS"),
            ("repeat_events", "AUTO-REPEATS"),
            ("redacted_events", "REDACTED EVENTS"),
            ("anomaly", "RATE ANOMALY"),
        )
        for index, (key, caption) in enumerate(counter_specs):
            row, column = divmod(index, 3)
            cell = QWidget()
            cell_layout = QVBoxLayout(cell)
            cell_layout.setContentsMargins(0, 0, 0, 0)
            cell_layout.setSpacing(2)
            heading = QLabel(caption)
            heading.setObjectName("Heading")
            value = QLabel("-")
            value.setObjectName("Value")
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cell_layout.addWidget(heading)
            cell_layout.addWidget(value)
            counters.addWidget(cell, row, column)
            self._counters[key] = value
        for column in range(3):
            counters.setColumnStretch(column, 1)
        root.addLayout(counters)

        # -- category breakdown -------------------------------------------- #
        category_box = QGroupBox("Key-Category Distribution")
        category_layout = QVBoxLayout(category_box)
        category_layout.setSpacing(6)
        self._category_bar = QProgressBar()
        self._category_bar.setRange(0, 100)
        self._category_bar.setValue(0)
        self._category_bar.setFormat("%p% of filtered events")
        category_layout.addWidget(self._category_bar)
        self._category_text = QLabel("No events recorded yet.")
        self._category_text.setWordWrap(True)
        category_layout.addWidget(self._category_text)
        self._category_chart = SimpleBarChart(
            orientation=SimpleBarChart.ORIENTATION_HORIZONTAL,
            empty_text="No key-category data yet.",
        )
        category_layout.addWidget(self._category_chart)
        root.addWidget(category_box)

        # -- application breakdown ----------------------------------------- #
        application_box = QGroupBox("Application Classification")
        application_layout = QVBoxLayout(application_box)
        application_layout.setSpacing(6)
        self._application_text = QLabel("No applications observed yet.")
        self._application_text.setWordWrap(True)
        self._application_text.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        application_layout.addWidget(self._application_text)

        self._timeline_text = QLabel("Timeline: -")
        self._timeline_text.setWordWrap(True)
        application_layout.addWidget(self._timeline_text)
        root.addWidget(application_box)

        # -- timeline chart -------------------------------------------------- #
        timeline_box = QGroupBox("Events Over Time (per minute)")
        timeline_layout = QVBoxLayout(timeline_box)
        timeline_layout.setSpacing(6)
        self._timeline_chart = SimpleBarChart(empty_text="No timeline data yet.")
        timeline_layout.addWidget(self._timeline_chart)
        root.addWidget(timeline_box)

        # -- repeats -------------------------------------------------------- #
        repeats_box = QGroupBox("Repeated-Key / Rollover Analysis")
        repeats_layout = QVBoxLayout(repeats_box)
        self._repeat_text = QLabel("No repeated keys detected yet.")
        self._repeat_text.setWordWrap(True)
        self._repeat_text.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        repeats_layout.addWidget(self._repeat_text)
        root.addWidget(repeats_box)
        root.addStretch(1)

    def update_stats(self, stats: DashboardStats) -> None:
        """Refresh every counter and breakdown from a dashboard snapshot."""
        self._counters["total_events"].setText(f"{stats.total_events:,}")
        self._counters["events_per_minute"].setText(f"{stats.events_per_minute:,.1f}")
        self._counters["unique_keys"].setText(f"{stats.unique_keys:,}")
        self._counters["session_duration"].setText(stats.duration_text)
        self._counters["key_down"].setText(f"{stats.key_down:,}")
        self._counters["key_up"].setText(f"{stats.key_up:,}")

        modifier_total = sum(count for _name, count in stats.modifier_series)
        function_total = sum(count for _name, count in stats.function_series)
        navigation_total = sum(count for _name, count in stats.navigation_series)
        self._counters["modifier_keys"].setText(f"{modifier_total:,}")
        self._counters["function_keys"].setText(f"{function_total:,}")
        self._counters["navigation_keys"].setText(f"{navigation_total:,}")
        self._counters["repeat_events"].setText(
            f"{stats.repeat_events:,} ({stats.repeat_ratio:.1f}%)"
        )
        self._counters["redacted_events"].setText(f"{stats.redacted_events:,}")

        anomaly_colour = {
            "NORMAL": COLOUR_ACTIVE,
            "ELEVATED": COLOUR_WARNING,
            "ANOMALOUS": COLOUR_STOPPED,
        }.get(stats.anomaly.display_level, COLOUR_NEUTRAL)
        self._counters["anomaly"].setText(stats.anomaly.display_level)
        self._counters["anomaly"].setStyleSheet(f"color: {anomaly_colour.name()}; font-weight: bold;")

        if stats.category_percentages:
            dominant_name, dominant_share = max(stats.category_percentages, key=lambda p: p[1])
            self._category_bar.setValue(int(round(dominant_share)))
            self._category_bar.setFormat(f"{dominant_name} - %p% of filtered events")
            self._category_text.setText(
                " · ".join(f"{name} {share:.1f}%" for name, share in stats.category_percentages)
            )
            self._category_chart.set_series(
                [(name, share) for name, share in stats.category_percentages],
                colour=COLOUR_ACTIVE,
            )
        else:
            self._category_bar.setValue(0)
            self._category_text.setText("No events recorded yet.")
            self._category_chart.clear()

        if stats.application_series:
            self._application_text.setText(
                " · ".join(
                    f"{name}: {count:,}" for name, count in stats.application_series[:8]
                )
            )
        else:
            self._application_text.setText("No applications observed yet.")

        if stats.timeline_series:
            peak_bucket, peak = max(stats.timeline_series, key=lambda item: item[1])
            self._timeline_text.setText(
                f"Timeline spans {len(stats.timeline_series)} minute bucket(s); "
                f"peak {peak:,} events at {peak_bucket}. {stats.anomaly.message}"
            )
            self._timeline_chart.set_series(
                stats.timeline_series,
                colour=COLOUR_WARNING if stats.anomaly.display_level != "NORMAL" else COLOUR_INFO,
            )
        else:
            self._timeline_text.setText(f"Timeline: - {stats.anomaly.message}")
            self._timeline_chart.clear()

        if stats.repeat_series:
            lines = [
                f"{name}: {total:,} event(s), {repeats:,} auto-repeat(s)"
                for name, total, repeats in stats.repeat_series[:8]
            ]
            self._repeat_text.setText("\n".join(lines))
        else:
            self._repeat_text.setText("No repeated keys detected yet.")


class FilterPanel(QWidget):
    """Search / filter controls for the event table."""

    filtersChanged = Signal()

    ALL_TEXT: Final[str] = "All"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setHorizontalSpacing(8)
        layout.setVerticalSpacing(6)

        # Row 0: text search + quick clears
        search_caption = QLabel("SEARCH BY KEY")
        search_caption.setObjectName("Heading")
        layout.addWidget(search_caption, 0, 0)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("e.g. F5, Enter, Numpad 1, A")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._emit_changed)
        layout.addWidget(self.search_edit, 1, 0, 1, 2)

        # Row 0/1 column 2-3: category + event type
        self.category_combo = self._make_combo(layout, "KEY CATEGORY", 0, 2)
        self.event_type_combo = self._make_combo(layout, "EVENT TYPE", 0, 3)
        self.event_type_combo.addItems([self.ALL_TEXT, EventType.KEY_DOWN.value,
                                        EventType.KEY_UP.value])

        # Row 2: application class + session
        self.application_combo = self._make_combo(layout, "APPLICATION CLASS", 2, 0)
        self.application_combo.setMinimumWidth(190)
        self.session_combo = self._make_combo(layout, "SESSION", 2, 1)
        self.session_combo.setMinimumWidth(190)

        # Row 3: date range
        date_from_caption = QLabel("DATE FROM")
        date_from_caption.setObjectName("Heading")
        layout.addWidget(date_from_caption, 3, 0)
        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDisplayFormat("yyyy-MM-dd")
        self.date_from.dateChanged.connect(self._emit_changed)
        layout.addWidget(self.date_from, 4, 0)

        date_to_caption = QLabel("DATE TO")
        date_to_caption.setObjectName("Heading")
        layout.addWidget(date_to_caption, 3, 1)
        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDisplayFormat("yyyy-MM-dd")
        self.date_to.dateChanged.connect(self._emit_changed)
        layout.addWidget(self.date_to, 4, 1)

        # Row 3/4 column 2: time range
        time_caption = QLabel("TIME RANGE")
        time_caption.setObjectName("Heading")
        layout.addWidget(time_caption, 3, 2)
        time_row = QHBoxLayout()
        self.time_from = QTimeEdit()
        self.time_from.setDisplayFormat("HH:mm:ss")
        self.time_from.timeChanged.connect(self._emit_changed)
        self.time_to = QTimeEdit()
        self.time_to.setDisplayFormat("HH:mm:ss")
        self.time_to.timeChanged.connect(self._emit_changed)
        time_row.addWidget(self.time_from)
        time_row.addWidget(QLabel("to"))
        time_row.addWidget(self.time_to)
        layout.addLayout(time_row, 4, 2, 1, 2)

        # Row 5: toggles + clear
        self.repeats_only = QCheckBox("Auto-repeats only")
        self.repeats_only.toggled.connect(self._emit_changed)
        layout.addWidget(self.repeats_only, 5, 0)

        self.clear_button = QPushButton("Clear Filters")
        self.clear_button.clicked.connect(self.clear_filters)
        layout.addWidget(self.clear_button, 5, 1)

        self.refresh_button = QPushButton("Refresh Values")
        self.refresh_button.setToolTip(
            "Reload the Application / Session filter lists from the database."
        )
        self.refresh_button.clicked.connect(self.filtersChanged)
        layout.addWidget(self.refresh_button, 5, 2)

        self.result_label = QLabel("Showing 0 of 0 events")
        self.result_label.setStyleSheet(f"color: {COLOUR_MUTED};")
        layout.addWidget(self.result_label, 5, 3)

        # Row 6: session scoping
        self.only_current_check = QCheckBox("Current session only")
        self.only_current_check.setChecked(True)
        self.only_current_check.setToolTip(
            "Scope the table, dashboard and export to the session being recorded "
            "instead of every session in the database."
        )
        self.only_current_check.toggled.connect(self._emit_changed)
        layout.addWidget(self.only_current_check, 6, 0, 1, 2)

        #: Session the view is scoped to while ``only_current_check`` is set.
        self.current_session_id: str = ""

        layout.setColumnStretch(0, 2)
        layout.setColumnStretch(1, 2)
        layout.setColumnStretch(2, 2)
        layout.setColumnStretch(3, 2)

        # The editors start out with an invalid date/time, which would silently
        # hide every stored event. Seed a window that always matches.
        for widget in (self.date_from, self.date_to, self.time_from, self.time_to):
            widget.blockSignals(True)
        self._reset_defaults()
        for widget in (self.date_from, self.date_to, self.time_from, self.time_to):
            widget.blockSignals(False)

    def _reset_defaults(self) -> None:
        """Apply the default, always-matching date/time window."""
        today = QDate.currentDate()
        self.date_from.setDate(today.addYears(-1))
        self.date_to.setDate(today.addYears(1))
        self.time_from.setTime(QTime(0, 0, 0))
        self.time_to.setTime(QTime(23, 59, 59))

    # -- construction helpers ---------------------------------------------- #
    def _make_combo(self, layout: QGridLayout, caption: str, row: int, column: int) -> QComboBox:
        label = QLabel(caption)
        label.setObjectName("Heading")
        layout.addWidget(label, row, column)
        combo = QComboBox()
        combo.addItem(self.ALL_TEXT)
        combo.currentIndexChanged.connect(self._emit_changed)
        layout.addWidget(combo, row + 1, column)
        return combo

    def _emit_changed(self, *_args: Any) -> None:
        self.filtersChanged.emit()

    # -- state -------------------------------------------------------------- #
    def clear_filters(self) -> None:
        """Reset every filter to its default (does not touch stored data)."""
        blocked = [self.search_edit.blockSignals(True),
                   self.category_combo.blockSignals(True),
                   self.event_type_combo.blockSignals(True),
                   self.application_combo.blockSignals(True),
                   self.session_combo.blockSignals(True),
                   self.date_from.blockSignals(True),
                   self.date_to.blockSignals(True),
                   self.time_from.blockSignals(True),
                   self.time_to.blockSignals(True),
                   self.repeats_only.blockSignals(True)]
        self.search_edit.clear()
        for combo in (self.category_combo, self.event_type_combo,
                      self.application_combo, self.session_combo):
            combo.setCurrentIndex(0)
        self._reset_defaults()
        self.repeats_only.setChecked(False)
        for widget in (self.search_edit, self.category_combo, self.event_type_combo,
                       self.application_combo, self.session_combo, self.date_from,
                       self.date_to, self.time_from, self.time_to, self.repeats_only):
            widget.blockSignals(blocked.pop(0))
        self._emit_changed()

    def populate_dynamic_values(
        self,
        categories: Sequence[str],
        applications: Sequence[str],
        sessions: Sequence[tuple[str, str]],
    ) -> None:
        """Refresh the combo box options from the database."""
        def refill(combo: QComboBox, values: Sequence[str]) -> None:
            current = combo.currentText()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem(self.ALL_TEXT)
            for value in values:
                combo.addItem(value)
            index = combo.findText(current)
            combo.setCurrentIndex(index if index >= 0 else 0)
            combo.blockSignals(False)

        refill(self.category_combo, categories)
        refill(self.application_combo, applications)

        self.session_combo.blockSignals(True)
        current = self.session_combo.currentText()
        self.session_combo.clear()
        self.session_combo.addItem(self.ALL_TEXT)
        for session_id, caption in sessions:
            self.session_combo.addItem(f"{caption} - {session_id}")
        index = self.session_combo.findText(current)
        self.session_combo.setCurrentIndex(index if index >= 0 else 0)
        self.session_combo.blockSignals(False)

    # -- query construction -------------------------------------------------- #
    def build_filter(self, *, limit: int = 5000) -> EventFilter:
        """Translate the widget state into a sanitised :class:`EventFilter`."""
        session_text = self.session_combo.currentText()
        session_id = None
        import re
        m = re.search(r'(S-[0-9A-F]{12})', session_text)
        if m:
            session_id = m.group(1)
        if self.only_current_check.isChecked() and self.current_session_id:
            session_id = self.current_session_id

        return EventFilter(
            session_id=session_id,
            key_contains=self.search_edit.text().strip(),
            key_category=self._selected(self.category_combo),
            event_type=self._selected(self.event_type_combo),
            application_class=self._selected(self.application_combo),
            date_from=self.date_from.date().toString("yyyy-MM-dd"),
            date_to=self.date_to.date().toString("yyyy-MM-dd"),
            time_from=self.time_from.time().toString("HH:mm:ss"),
            time_to=self.time_to.time().toString("HH:mm:ss"),
            repeats_only=self.repeats_only.isChecked(),
            limit=limit,
        ).sanitized()

    @staticmethod
    def _selected(combo: QComboBox) -> str | None:
        text = combo.currentText()
        return None if text == FilterPanel.ALL_TEXT or not text else text

    def set_result_text(self, shown: int, total: int) -> None:
        self.result_label.setText(f"Showing {shown:,} of {total:,} events")

    def set_current_session(self, session_id: str) -> None:
        """Scope "current session only" to `session_id` and refresh the view."""
        self.current_session_id = session_id or ""
        self._emit_changed()

    def current_filtered_session_id(self) -> str | None:
        """The session id the active filter resolves to, if any."""
        return self.build_filter().session_id


class SettingsDialog(QDialog):
    """Analyst preferences, including the privacy and location settings."""

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(560)
        self._config = config

        layout = QVBoxLayout(self)

        # -- privacy -------------------------------------------------------- #
        privacy = QGroupBox("Privacy (privacy-by-default)")
        privacy_form = QFormLayout(privacy)

        self.redaction_check = QCheckBox(
            f"Redaction mode - record sensitive windows as {REDACTED_WINDOW_PLACEHOLDER}"
        )
        self.redaction_check.setChecked(config.redaction_enabled)
        self.redaction_check.setToolTip(
            "Enabled by default. Disable only under an explicit engagement scope."
        )
        privacy_form.addRow(self.redaction_check)

        self.classify_check = QCheckBox(
            "Record foreground application class (no window titles are stored)"
        )
        self.classify_check.setChecked(config.classify_foreground_application)
        privacy_form.addRow(self.classify_check)

        location_caption = QLabel("Device / location label (no GPS, no precise location)")
        location_caption.setObjectName("Heading")
        self.location_edit = QLineEdit(sanitize_label(config.location_label, max_length=120))
        self.location_edit.setPlaceholderText("Local Device / Test Machine / Lab Workstation")
        privacy_form.addRow(location_caption, self.location_edit)

        self.patterns_edit = QPlainTextEdit()
        self.patterns_edit.setPlaceholderText(
            "One case-insensitive substring per line, e.g. 'keepass' or 'sign in'"
        )
        self.patterns_edit.setPlainText("\n".join(config.sensitive_window_patterns))
        self.patterns_edit.setFixedHeight(110)
        privacy_form.addRow("Sensitive window patterns", self.patterns_edit)
        layout.addWidget(privacy)

        # -- collection ----------------------------------------------------- #
        collection = QGroupBox("Collection")
        collection_form = QFormLayout(collection)

        self.simulation_check = QCheckBox(
            "Simulation Mode - generate synthetic events, never read the real keyboard"
        )
        self.simulation_check.setChecked(config.simulation_mode)
        collection_form.addRow(self.simulation_check)

        self.consent_check = QCheckBox("Require consent acknowledgement before Start")
        self.consent_check.setChecked(config.require_consent_acknowledgement)
        collection_form.addRow(self.consent_check)

        self.dedupe_spin = QSpinBox()
        self.dedupe_spin.setRange(0, 1000)
        self.dedupe_spin.setValue(config.dedupe_window_ms)
        self.dedupe_spin.setSuffix(" ms")
        self.dedupe_spin.setToolTip(
            "Debounce window: identical (key, event) pairs closer together than "
            "this are treated as duplicates."
        )
        collection_form.addRow("Debounce / dedupe window", self.dedupe_spin)

        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, 100_000)
        self.rate_spin.setValue(config.max_events_per_second)
        self.rate_spin.setSingleStep(50)
        collection_form.addRow("Max events / second", self.rate_spin)

        self.cap_spin = QSpinBox()
        self.cap_spin.setRange(1, 10_000_000)
        self.cap_spin.setSingleStep(10_000)
        self.cap_spin.setValue(config.max_events_per_session)
        collection_form.addRow("Max events / session", self.cap_spin)

        self.repeat_spin = QSpinBox()
        self.repeat_spin.setRange(1, 1000)
        self.repeat_spin.setValue(config.repeat_threshold)
        self.repeat_spin.setToolTip(
            "Consecutive key-down events for the same key before it is flagged as "
            "an auto-repeat (key rollover)."
        )
        collection_form.addRow("Repeat / rollover threshold", self.repeat_spin)

        self.sim_rate_spin = QSpinBox()
        self.sim_rate_spin.setRange(1, 1000)
        self.sim_rate_spin.setValue(int(config.simulation_events_per_second))
        self.sim_rate_spin.setSuffix(" /s")
        collection_form.addRow("Simulation event rate", self.sim_rate_spin)

        self.refresh_spin = QSpinBox()
        self.refresh_spin.setRange(50, 5000)
        self.refresh_spin.setSingleStep(50)
        self.refresh_spin.setSuffix(" ms")
        self.refresh_spin.setValue(config.gui_refresh_ms)
        collection_form.addRow("GUI refresh interval", self.refresh_spin)
        layout.addWidget(collection)

        # -- security notice -------------------------------------------------- #
        notice = QGroupBox("Security policy (always enforced)")
        notice_layout = QVBoxLayout(notice)
        notice_text = QPlainTextEdit()
        notice_text.setReadOnly(True)
        notice_text.setPlainText("\n".join(f"• {line}" for line in SECURITY_GUARANTEES))
        notice_text.setFixedHeight(150)
        notice_layout.addWidget(notice_text)
        layout.addWidget(notice)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def apply_to(self, config: AppConfig) -> list[str]:
        """Copy widget values into ``config`` and return any validation problems."""
        config.redaction_enabled = self.redaction_check.isChecked()
        config.classify_foreground_application = self.classify_check.isChecked()
        config.location_label = sanitize_label(self.location_edit.text(), max_length=120)
        config.sensitive_window_patterns = [
            sanitize_label(line, max_length=80)
            for line in self.patterns_edit.toPlainText().splitlines()
            if line.strip()
        ][:200]
        config.simulation_mode = self.simulation_check.isChecked()
        config.require_consent_acknowledgement = self.consent_check.isChecked()
        config.dedupe_window_ms = self.dedupe_spin.value()
        config.max_events_per_second = self.rate_spin.value()
        config.max_events_per_session = self.cap_spin.value()
        config.repeat_threshold = self.repeat_spin.value()
        config.simulation_events_per_second = float(self.sim_rate_spin.value())
        config.gui_refresh_ms = self.refresh_spin.value()
        return config.validate()


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(
        self,
        config: AppConfig,
        database: Database,
        store: ConfigStore,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.config = config
        self.database = database
        self.store = store
        self.monitor = EventMonitor(config, database, self)

        self._consent_acknowledged = not config.require_consent_acknowledgement
        self._session_start: datetime | None = None
        self._pending_events = 0

        self.setWindowTitle(f"{APP_TITLE} v{APP_VERSION}")
        self.resize(1500, 940)
        self.setMinimumSize(1150, 760)

        self._build_ui()
        self._build_menu()
        self._connect_signals()
        self._refresh_filter_values()
        self._reload_table()
        self._update_status(active=False)
        self.statusBar().showMessage(f"Database: {database.path}")

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(config.gui_refresh_ms)
        self._refresh_timer.timeout.connect(self._on_refresh_tick)
        self._refresh_timer.start()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 8)
        root.setSpacing(8)

        # Consent banner ---------------------------------------------------- #
        banner = QLabel(CONSENT_TEXT)
        banner.setObjectName("Banner")
        banner.setWordWrap(True)
        banner.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(banner)

        # Toolbar ----------------------------------------------------------- #
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(8)

        self.start_button = QPushButton("▶  Start Logging")
        self.start_button.setObjectName("StartButton")
        self.start_button.setToolTip("Begin recording (requires consent acknowledgement).")
        self.start_button.setMinimumWidth(150)

        self.stop_button = QPushButton("■  Stop Logging")
        self.stop_button.setObjectName("StopButton")
        self.stop_button.setToolTip("Stop recording and finalize the session.")
        self.stop_button.setMinimumWidth(150)
        self.stop_button.setEnabled(False)

        self.export_button = QPushButton("⬇  Export Excel")
        self.export_button.setToolTip("Export the current filtered view to an .xlsx report.")
        self.export_button.setMinimumWidth(150)

        self.clear_button = QPushButton("🗑  Clear Records")
        self.clear_button.setToolTip("Delete all stored events from the local database.")
        self.clear_button.setMinimumWidth(150)

        self.settings_button = QPushButton("⚙  Settings")
        self.settings_button.setMinimumWidth(130)

        self.consent_button = QPushButton("Consent: NOT ACKNOWLEDGED")
        self.consent_button.setCheckable(True)
        self.consent_button.setToolTip(
            "Confirm you are authorized to monitor activity on this device."
        )
        self.consent_button.setMinimumWidth(230)

        for widget in (self.consent_button, self.start_button, self.stop_button,
                       self.export_button, self.clear_button, self.settings_button):
            toolbar_layout.addWidget(widget)
        toolbar_layout.addStretch(1)
        root.addWidget(toolbar)

        # Status strip ------------------------------------------------------ #
        self.status_strip = StatusStrip()
        root.addWidget(self.status_strip)

        # Tabs: events + dashboard ------------------------------------------- #
        self.tabs = QTabWidget()

        # Events tab
        events_tab = QWidget()
        events_layout = QVBoxLayout(events_tab)
        events_layout.setSpacing(8)

        self.filter_panel = FilterPanel()
        events_layout.addWidget(self.filter_panel)

        self.table = QTableView()
        self.model = EventTableModel(self)
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setDefaultSectionSize(20)
        self.table.verticalHeader().setVisible(True)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setWordWrap(False)
        events_layout.addWidget(self.table, 1)

        self.tabs.addTab(events_tab, "Keyboard Events")

        # Dashboard tab
        self.dashboard = DashboardPanel()
        self.tabs.addTab(self.dashboard, "Dashboard")
        root.addWidget(self.tabs, 1)

        self.setCentralWidget(central)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction("Export Excel…", self._on_export)
        file_menu.addAction("Clear Records…", self._on_clear_records)
        file_menu.addAction("Reveal Database Folder", self._on_reveal_database)
        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        session_menu = self.menuBar().addMenu("&Session")
        session_menu.addAction("Start Logging", self._on_start)
        session_menu.addAction("Stop Logging", self._on_stop)
        session_menu.addSeparator()
        session_menu.addAction("Acknowledge Consent", self._on_menu_acknowledge_consent)

        settings_menu = self.menuBar().addMenu("&View")
        settings_menu.addAction("Settings…", self._on_settings)
        settings_menu.addAction("Clear Filters", self.filter_panel.clear_filters)
        settings_menu.addAction("Refresh Now", self._reload_table)
        settings_menu.addSeparator()
        settings_menu.addAction("Show Security Policy", self._on_show_policy)

    def _connect_signals(self) -> None:
        self.start_button.clicked.connect(self._on_start)
        self.stop_button.clicked.connect(self._on_stop)
        self.export_button.clicked.connect(self._on_export)
        self.clear_button.clicked.connect(self._on_clear_records)
        self.settings_button.clicked.connect(self._on_settings)
        self.consent_button.toggled.connect(self._on_toggle_consent)

        self.filter_panel.filtersChanged.connect(self._reload_table)

        self.monitor.runningChanged.connect(self._on_running_changed)
        self.monitor.batchReady.connect(self._on_batch)
        self.monitor.notice.connect(self._on_notice)
        self.monitor.failed.connect(self._on_failure)
        self.monitor.sessionStarted.connect(self._on_session_started)
        self.monitor.sessionFinished.connect(self._on_session_finished)

        self._update_button_states()

    # ------------------------------------------------------------------ #
    # Toolbar actions
    # ------------------------------------------------------------------ #
    def _on_menu_acknowledge_consent(self) -> None:
        """Menu entry point: tick the consent switch and confirm from there.

        ``QAction.triggered`` emits ``checked=False``, so the consent handler
        cannot be wired to the menu directly or the confirmation would never
        be requested.
        """
        if self.consent_button.isChecked():
            self._on_show_policy()
            return
        self.consent_button.setChecked(True)

    def _on_toggle_consent(self, acknowledged: bool) -> None:
        """Record (or revoke) the analyst's consent acknowledgement."""
        if acknowledged:
            answer = QMessageBox.question(
                self,
                "Confirm authorization",
                "Do you have the explicit consent of the person using this device to "
                "record keyboard event metadata?\n\n"
                "Only metadata is recorded - never passwords, tokens or typed text.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.consent_button.blockSignals(True)
                self.consent_button.setChecked(False)
                self.consent_button.blockSignals(False)
                return
        self._consent_acknowledged = acknowledged
        self.consent_button.setText(
            "Consent: ACKNOWLEDGED" if acknowledged else "Consent: NOT ACKNOWLEDGED"
        )
        self.consent_button.setStyleSheet(
            f"color: {COLOUR_ACTIVE.name() if acknowledged else COLOUR_WARNING.name()};"
            " font-weight: bold;"
        )
        LOGGER.info("Consent acknowledgement set to %s", acknowledged)
        self._update_button_states()

    def _on_start(self) -> None:
        """Start a monitoring session - only ever from an explicit button press."""
        if self.monitor.is_running:
            self._show_warning("Already running", "A monitoring session is already active.")
            return
        if self.config.require_consent_acknowledgement and not self._consent_acknowledged:
            self._show_warning(
                "Consent required",
                "Acknowledge the consent notice before starting a monitoring session.",
            )
            return
        try:
            self.monitor.start(consent_acknowledged=True)
        except MonitoringError as exc:
            self._show_error("Could not start monitoring", str(exc))
        except DatabaseError as exc:
            self._show_error("Database error", str(exc))

    def _on_stop(self) -> None:
        """Stop the active session and finalize its database record."""
        if not self.monitor.is_running:
            return
        self.stop_button.setEnabled(False)
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            self.monitor.stop()
        finally:
            self.unsetCursor()
        # Refresh immediately rather than waiting for the worker's queued
        # notification, so the status strip is correct the moment we return.
        self._update_status(active=self.monitor.is_running)
        self._update_button_states()

    def _on_export(self) -> None:
        """Ask for a destination and write an .xlsx report."""
        criteria = self.filter_panel.build_filter()
        default_name = (
            f"keyboard_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        )
        suggestion = str(data_dir() / "exports" / default_name)
        from PySide6.QtWidgets import QFileDialog

        destination, _selected = QFileDialog.getSaveFileName(
            self, "Export keyboard events to Excel", suggestion, "Excel Workbook (*.xlsx)"
        )
        if not destination:
            return
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            result = export_to_excel(
                self.database,
                destination,
                criteria=criteria,
                redaction_enabled=self.config.redaction_enabled,
                sensitive_patterns=self.config.sensitive_window_patterns,
                notice=SECURITY_GUARANTEES,
            )
        except ExportError as exc:
            self._show_error("Excel export failed", str(exc))
            return
        except DatabaseError as exc:
            self._show_error("Database error", str(exc))
            return
        finally:
            self.unsetCursor()

        message = (
            f"Exported {result.event_rows:,} event row(s) and "
            f"{result.session_rows} session summary row(s) to:\n\n{result.path}"
        )
        if result.warnings:
            message += "\n\n" + "\n".join(result.warnings)
        message += "\n\nThe report contains event metadata only - no typed text or secrets."
        QMessageBox.information(self, "Export complete", message)
        self.statusBar().showMessage(f"Exported to {result.path}", 8000)

    def _on_clear_records(self) -> None:
        """Delete every stored event after explicit confirmation."""
        if self.monitor.is_running:
            self._show_warning(
                "Stop logging first",
                "Stop the active monitoring session before clearing records.",
            )
            return
        confirm = QMessageBox.question(
            self,
            "Clear all recorded events",
            "This permanently deletes every keyboard event stored in:\n"
            f"{self.database.path}\n\n"
            "Session history is kept but its counters are reset.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            deleted = self.database.clear_records()
        except DatabaseError as exc:
            self._show_error("Database error", str(exc))
            return
        try:
            self.database.vacuum()
        except DatabaseError:  # pragma: no cover - VACUUM is best effort
            pass
        self._reload_table()
        self._refresh_filter_values()
        self._update_dashboard()
        self._update_status(active=False)
        self.statusBar().showMessage(f"Cleared {deleted:,} record(s)", 6000)

    def _on_settings(self) -> None:
        dialog = SettingsDialog(self.config, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        problems = dialog.apply_to(self.config)
        if problems:
            QMessageBox.warning(
                self,
                "Settings clamped",
                "Some values were outside the permitted range and were adjusted:\n\n"
                + "\n".join(f"• {problem}" for problem in problems),
            )
        self.store.save(self.config)
        self._refresh_timer.setInterval(self.config.gui_refresh_ms)
        self._on_refresh_tick()
        self.statusBar().showMessage("Settings saved", 5000)

    def _on_reveal_database(self) -> None:
        """Open the folder containing the database in the platform file browser."""
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl

        folder = self.database.path.parent
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _on_show_policy(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Security policy")
        dialog.resize(720, 520)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(
            "ENFORCED GUARANTEES\n"
            + "\n".join(f"• {line}" for line in SECURITY_GUARANTEES)
            + "\n\nDELIBERATELY NOT IMPLEMENTED\n"
            + "\n".join(f"• {line}" for line in NOT_IMPLEMENTED_BY_DESIGN)
        )
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.exec()

    # ------------------------------------------------------------------ #
    # Monitor callbacks
    # ------------------------------------------------------------------ #
    def _on_session_started(self, session_id: str) -> None:
        self._session_start = datetime.now()
        self.status_strip.set_started(self._session_start)
        self.status_strip.set_event_count(0)
        # Scope the view to the new session so a fresh recording starts on an
        # empty table instead of showing rows from earlier sessions.
        self._refresh_filter_values()
        self.filter_panel.set_current_session(session_id)  # also reloads the table
        self._update_dashboard()
        self.statusBar().showMessage(
            f"Session {session_id} started - mode: {self.monitor.mode}"
        )

    def _on_running_changed(self, active: bool) -> None:
        self._update_status(active=active)
        self._update_button_states()

    def _on_session_finished(self, session_id: str, count: int) -> None:
        self._session_start = None
        self.status_strip.set_started(None)
        self.status_strip.set_duration(None)
        self._reload_table()
        self._refresh_filter_values()
        self._update_dashboard()
        self.statusBar().showMessage(
            f"Session {session_id} stopped - {count:,} event(s) recorded", 8000
        )

    def _on_batch(self, events: Sequence[KeyEvent]) -> None:
        """Handle a flushed batch on the GUI thread."""
        self._pending_events += len(events)
        self.status_strip.set_event_count(self.monitor.events_this_session)
        if self._pending_events >= self.config.table_page_size // 2:
            self._pending_events = 0
            self._reload_table()
            self._update_dashboard()

    def _on_notice(self, message: str) -> None:
        self.statusBar().showMessage(message, 8000)
        LOGGER.info("Notice: %s", message)

    def _on_failure(self, title: str, detail: str) -> None:
        """Surface a worker failure; stop the session cleanly."""
        LOGGER.error("%s: %s", title, detail)
        if self.monitor.is_running:
            self.monitor.stop()
        self._show_error(title, detail)

    # ------------------------------------------------------------------ #
    # Periodic refresh
    # ------------------------------------------------------------------ #
    def _on_refresh_tick(self) -> None:
        self._update_duration()
        if self.monitor.is_running:
            self._update_dashboard()
            self._refresh_filter_values()

    def _update_duration(self) -> None:
        if self._session_start is None:
            self.status_strip.set_duration(None)
            return
        self.status_strip.set_duration(
            (datetime.now() - self._session_start).total_seconds()
        )

    def _reload_table(self) -> None:
        """Re-run the active filter and repopulate the table."""
        criteria = self.filter_panel.build_filter(limit=self.config.table_page_size * 10)
        try:
            rows = self.database.query_events(criteria)
            total = self.database.count_events(criteria)
        except DatabaseError as exc:
            LOGGER.warning("Could not refresh the event table: %s", exc)
            self.statusBar().showMessage(f"Table refresh failed: {exc}", 6000)
            return
        self.model.set_rows(rows)
        self.filter_panel.set_result_text(len(rows), total)

    def _update_dashboard(self) -> None:
        criteria = self.filter_panel.build_filter(limit=1_000_000)
        session = None
        if self.monitor.is_running and self.monitor.session_id:
            session = self.database.get_session(self.monitor.session_id)
        stats = compute_dashboard(self.database, criteria, session)
        self.dashboard.update_stats(stats)

    def _refresh_filter_values(self) -> None:
        """Reload category / application / session options from the database."""
        try:
            categories = self.database.distinct_values("key_category")
            applications = self.database.distinct_values("application_class")
            sessions = [
                (record.session_id, record.started_local or record.started_at)
                for record in self.database.get_sessions(limit=200)
            ]
        except DatabaseError as exc:  # pragma: no cover - defensive
            LOGGER.warning("Could not refresh filter values: %s", exc)
            return
        self.filter_panel.populate_dynamic_values(categories, applications, sessions)

    # ------------------------------------------------------------------ #
    # Status helpers
    # ------------------------------------------------------------------ #
    def _update_status(self, *, active: bool) -> None:
        self.status_strip.set_active(active)
        self.status_strip.set_event_count(self.monitor.events_this_session)
        if not active:
            self.status_strip.set_started(None)
            self.status_strip.set_duration(None)

    def _update_button_states(self) -> None:
        """Enable exactly one of Start / Stop, honouring the consent gate."""
        running = self.monitor.is_running
        can_start = (not running) and (
            self._consent_acknowledged
            or not self.config.require_consent_acknowledgement
        )
        self.start_button.setEnabled(can_start)
        self.stop_button.setEnabled(running)
        self.export_button.setEnabled(not running)
        self.clear_button.setEnabled(not running)
        self.settings_button.setEnabled(not running)
        self.consent_button.setEnabled(not running)

    def _show_error(self, title: str, detail: str) -> None:
        QMessageBox.critical(self, title, detail)

    def _show_warning(self, title: str, detail: str) -> None:
        QMessageBox.warning(self, title, detail)

    # ------------------------------------------------------------------ #
    # Shutdown
    # ------------------------------------------------------------------ #
    def closeEvent(self, event: Any) -> None:  # noqa: N802 - Qt naming
        """Stop the worker thread and close database connections cleanly."""
        self._refresh_timer.stop()
        if self.monitor.is_running:
            confirm = QMessageBox.question(
                self,
                "Monitoring is active",
                "A monitoring session is still running.\n\n"
                "Stop it and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirm != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        try:
            self.monitor.shutdown()
        except Exception as exc:  # pragma: no cover - shutdown must not hang the GUI
            LOGGER.warning("Error while stopping the monitor: %s", exc)
        try:
            self.database.close()
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("Error while closing the database: %s", exc)
        LOGGER.info("Application shutting down.")
        super().closeEvent(event)


def run(config: AppConfig, database: Database, store: ConfigStore) -> int:
    """Create the QApplication and show the main window (used by tests)."""
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication([])
    app.setStyleSheet(_stylesheet())
    window = MainWindow(config, database, store)
    window.show()
    return app.exec()
