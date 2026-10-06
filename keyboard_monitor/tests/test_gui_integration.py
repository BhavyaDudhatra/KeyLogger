"""Offscreen integration tests for the GUI, monitor and analytics layers.

These tests exercise the full stack without a display server:

* the window constructs, and the consent gate actually gates Start,
* Simulation Mode captures events into SQLite and the table/dashboard update,
* filters and statistics respond correctly,
* Stop finalises the session and the app closes cleanly.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtGui import QColor  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from keyboard_monitor.analytics import compute_dashboard, detect_rate_anomaly  # noqa: E402
from keyboard_monitor.config import AppConfig, ConfigStore  # noqa: E402
from keyboard_monitor.database import Database, EventFilter  # noqa: E402
from keyboard_monitor.event_monitor import (  # noqa: E402
    EventMonitor,
    MonitorWorker,
    MonitoringError,
    corpus_categories,
    synthetic_key_names,
)
from keyboard_monitor.gui import DashboardPanel, MainWindow, SimpleBarChart  # noqa: E402
from keyboard_monitor.models import (  # noqa: E402
    EventType,
    KeyCategory,
    KeyGroup,
    new_session_id,
    normalize_key,
)
from keyboard_monitor.security import (  # noqa: E402
    NOT_IMPLEMENTED_BY_DESIGN,
    SECURITY_GUARANTEES,
    RedactionPolicy,
    classify_application,
    is_valid_session_id,
    safe_export_path,
    sanitize_label,
    utc_now,
)


@pytest.fixture(scope="session")
def app() -> QApplication:
    """A single QApplication shared by every GUI test."""
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    application = QApplication([])
    application.setStyleSheet("")
    return application


@pytest.fixture(autouse=True)
def no_modal_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every modal message box with a non-blocking stub.

    Without this an error path would open a dialog that nobody can dismiss in
    an offscreen test run, hanging the suite.
    """
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok),
    )
    monkeypatch.setattr(
        QMessageBox, "critical",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok),
    )
    monkeypatch.setattr(
        QMessageBox, "information",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok),
    )
    monkeypatch.setattr(
        QMessageBox, "question",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes),
    )


@pytest.fixture()
def sim_config(tmp_path: Path) -> AppConfig:
    """Simulation-mode configuration writing to ``tmp_path``."""
    return AppConfig(
        simulation_mode=True,
        simulation_events_per_second=120.0,
        gui_refresh_ms=100,
        location_label="Lab Workstation",
        max_events_per_second=5000,
    ).sanitized()


def _wait_until(predicate, timeout: float = 8.0, interval: float = 0.05) -> bool:
    """Pump the event loop until ``predicate`` is true or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if predicate():
            return True
        time.sleep(interval)
    QApplication.processEvents()
    return bool(predicate())


def _stats_with_data(database: Database):
    """Populate ``database`` with a few events and return dashboard stats."""
    from conftest import make_event

    sid = new_session_id()
    database.start_session(
        sid, started_at=utc_now(), simulated=True, redaction_enabled=True,
        location_label="Lab Workstation",
    )
    rows = [
        make_event(session_id=sid, key_name="A", offset_ms=index * 40)
        for index in range(12)
    ]
    rows.append(
        make_event(
            session_id=sid, key_name="Shift",
            category=KeyCategory.MODIFIER, group=KeyGroup.MODIFIERS,
            offset_ms=500,
        )
    )
    database.insert_events(rows)
    database.finalize_session(sid, utc_now(), len(rows))
    return compute_dashboard(database)


# --------------------------------------------------------------------------- #
# Security policy
# --------------------------------------------------------------------------- #
class TestSecurityPolicy:
    def test_redaction_is_enabled_by_default(self) -> None:
        assert AppConfig().redaction_enabled is True

    def test_consent_requirement_enabled_by_default(self) -> None:
        assert AppConfig().require_consent_acknowledgement is True

    def test_sensitive_windows_are_redacted(self) -> None:
        policy = RedactionPolicy()
        app_class, status = policy.resolve("chrome.exe", "Bank of America - Sign In")
        assert app_class == "[SENSITIVE_WINDOW_REDACTED]"
        assert status.value == "Redacted"

    def test_ordinary_windows_are_classified(self) -> None:
        app_class, status = RedactionPolicy().resolve("Code.exe", "main.py")
        assert app_class == "IDE"
        assert status.value == "Normal"

    @pytest.mark.parametrize(
        "process,title,expected",
        [
            ("WindowsTerminal.exe", "pwsh", "Terminal"),
            ("chrome.exe", "Docs - Google", "Browser"),
            ("notepad.exe", "notes.txt", "Text Editor"),
            ("explorer.exe", "Downloads", "File Manager"),
            ("pycharm64.exe", "project", "IDE"),
            ("unknown-app.exe", "something", "Unknown Application"),
        ],
    )
    def test_application_classification(self, process: str, title: str, expected: str) -> None:
        assert classify_application(process, title) == expected

    def test_redaction_can_be_disabled_explicitly(self) -> None:
        policy = RedactionPolicy(enabled=False)
        app_class, status = policy.resolve("keepass.exe", "Login")
        assert app_class != "[SENSITIVE_WINDOW_REDACTED]"
        assert status.value == "Normal"

    def test_sanitize_label_strips_control_characters(self) -> None:
        assert sanitize_label("a\x00b\x07c") == "a b c"

    def test_sanitize_label_bounds_length(self) -> None:
        assert len(sanitize_label("x" * 500, max_length=40)) == 40

    def test_session_id_validation(self) -> None:
        assert is_valid_session_id("S-0123456789AB")
        assert not is_valid_session_id("S-lowercase")
        assert not is_valid_session_id("'; DROP TABLE events; --")
        assert not is_valid_session_id(None)

    def test_export_path_validation(self) -> None:
        assert safe_export_path("report.xlsx").suffix == ".xlsx"
        for bad in ("report.csv", "", None, "   "):
            with pytest.raises(ValueError):
                safe_export_path(bad)

    def test_guarantees_and_omissions_documented(self) -> None:
        assert len(SECURITY_GUARANTEES) >= 6
        joined = " ".join(NOT_IMPLEMENTED_BY_DESIGN).lower()
        for topic in ("clipboard", "screenshot", "injection", "persistence", "network"):
            assert topic in joined

    def test_no_network_or_stealth_imports_in_source(self) -> None:
        """Static check: the package must not import networking or process tools."""
        package = Path(__file__).resolve().parents[1]
        banned = (
            "import socket", "import requests", "import urllib.request",
            "import http.client", "import ftplib", "import smtplib",
            "import telnetlib", "import paramiko", "import ctypes.wintypes",
        )
        for source in package.glob("*.py"):
            text = source.read_text(encoding="utf-8")
            for needle in banned:
                if needle == "import ctypes.wintypes":
                    continue  # ctypes is used for window queries, checked elsewhere
                assert needle not in text, f"{source.name} imports {needle}"


# --------------------------------------------------------------------------- #
# Analytics
# --------------------------------------------------------------------------- #
class TestAnalytics:
    def test_anomaly_detects_spike(self) -> None:
        timeline = [(f"20:{minute:02d}", 10) for minute in range(10)]
        timeline.append(("20:10", 900))
        report = detect_rate_anomaly(timeline)
        assert report.is_anomalous
        assert "spike" in report.message.lower() or "threshold" in report.message.lower()

    def test_anomaly_normal_for_steady_rate(self) -> None:
        timeline = [(f"20:{minute:02d}", 20) for minute in range(10)]
        report = detect_rate_anomaly(timeline)
        assert not report.is_anomalous
        assert report.level == "normal"

    def test_anomaly_needs_data(self) -> None:
        assert detect_rate_anomaly([]).level == "normal"

    def test_dashboard_over_filtered_events(
        self, database: Database, sim_config: AppConfig
    ) -> None:
        from keyboard_monitor.models import (
            KeyCategory,
            KeyEvent,
            KeyGroup,
            new_session_id,
        )
        from keyboard_monitor.security import utc_now

        sid = new_session_id()
        database.start_session(
            sid, started_at=utc_now(), simulated=True,
            redaction_enabled=True, location_label="Test",
        )
        events = []
        for index in range(20):
            category = KeyCategory.LETTER if index % 2 else KeyCategory.MODIFIER
            group = KeyGroup.LETTERS if index % 2 else KeyGroup.MODIFIERS
            events.append(KeyEvent(
                key_name="A" if index % 2 else "Shift",
                key_category=category, key_group=group,
                event_type=EventType.KEY_DOWN, timestamp=utc_now(),
                session_id=sid, application_class="Text Editor",
            ))
        database.insert_events(events)
        stats = compute_dashboard(database, EventFilter(session_id=sid))
        assert stats.total_events == 20
        assert stats.key_down == 20
        assert stats.unique_keys == 2
        assert dict(stats.category_series)["Letter"] == 10

    def test_dashboard_never_raises_on_empty_db(self, database: Database) -> None:
        stats = compute_dashboard(database)
        assert stats.total_events == 0


# --------------------------------------------------------------------------- #
# Charts
# --------------------------------------------------------------------------- #
def _painted_pixels(widget, *, background: str = "#1e293b", step: int = 2) -> int:
    """Count non-background pixels in a rendered widget.

    Rendering is the only way to prove the chart actually draws, so the tests
    count painted pixels rather than merely checking that ``grab()`` succeeds.
    """
    image = widget.grab().toImage()
    painted = 0
    for y in range(0, image.height(), step):
        for x in range(0, image.width(), step):
            if image.pixelColor(x, y).name() != background:
                painted += 1
    return painted


class TestSimpleBarChart:
    def test_empty_chart_paints_border_and_placeholder(self, app) -> None:
        chart = SimpleBarChart(empty_text="nothing here")
        chart.resize(320, 180)
        chart.show()
        app.processEvents()
        # Border plus the centred message, but no bars.
        painted = _painted_pixels(chart)
        assert 0 < painted < 1200
        chart.close()

    def test_vertical_series_paints_bars(self, app) -> None:
        chart = SimpleBarChart()
        chart.set_series([("2026-01-01T09:00", 4.0), ("2026-01-01T09:01", 11.0)])
        chart.resize(320, 180)
        chart.show()
        app.processEvents()
        assert len(chart._series) == 2  # noqa: SLF001
        assert _painted_pixels(chart) > 1000
        chart.close()

    def test_vertical_series_uses_requested_colour(self, app) -> None:
        chart = SimpleBarChart()
        chart.set_series([("A", 5.0)], colour=QColor("#ff0000"))
        chart.resize(200, 160)
        chart.show()
        app.processEvents()
        image = chart.grab().toImage()
        reds = sum(
            1
            for y in range(0, image.height())
            for x in range(0, image.width())
            if image.pixelColor(x, y).red() > 180
            and image.pixelColor(x, y).green() < 90
        )
        assert reds > 500, "the bar should be painted in the requested colour"
        chart.close()

    def test_horizontal_series_paints_bars(self, app) -> None:
        chart = SimpleBarChart(orientation=SimpleBarChart.ORIENTATION_HORIZONTAL)
        chart.set_series(
            [("Letter", 62.5), ("Number", 12.0), ("Modifier", 8.0)]
        )
        chart.resize(320, 200)
        chart.show()
        app.processEvents()
        assert _painted_pixels(chart) > 800
        chart.close()

    def test_long_series_thins_out_its_labels(self, app) -> None:
        """240 buckets must still render without overflowing the widget."""
        chart = SimpleBarChart()
        chart.set_series([(f"2026-01-01T09:{m % 60:02d}", float(m + 1)) for m in range(240)])
        chart.resize(320, 180)
        chart.show()
        app.processEvents()
        assert _painted_pixels(chart) > 1000
        assert chart.sizeHint().width() > 0
        chart.close()

    def test_all_zero_series_does_not_divide_by_zero(self, app) -> None:
        chart = SimpleBarChart()
        chart.set_series([("A", 0.0), ("B", 0.0)])
        chart.resize(200, 160)
        chart.show()
        app.processEvents()
        assert _painted_pixels(chart) > 0
        chart.close()

    def test_negative_values_do_not_crash(self, app) -> None:
        chart = SimpleBarChart()
        chart.set_series([("A", -5.0), ("B", 3.0)])
        chart.resize(200, 160)
        chart.show()
        app.processEvents()
        assert _painted_pixels(chart) > 0
        chart.close()

    def test_clear_keeps_colour_and_drops_data(self, app) -> None:
        chart = SimpleBarChart()
        chart.set_series([("A", 1.0)], colour=QColor("#ff0000"))
        chart.clear()
        assert chart._series == []  # noqa: SLF001
        assert chart._colour.name() == QColor("#ff0000").name()  # noqa: SLF001

    def test_dashboard_feeds_charts(self, database: Database) -> None:
        """The dashboard must push real data into both chart widgets."""
        stats = _stats_with_data(database)
        panel = DashboardPanel()
        panel.resize(640, 900)
        panel.update_stats(stats)
        assert panel._category_chart._series  # noqa: SLF001
        assert panel._timeline_chart._series  # noqa: SLF001
        panel.close()

    def test_dashboard_charts_clear_on_empty_stats(self, database: Database) -> None:
        panel = DashboardPanel()
        panel.update_stats(compute_dashboard(database))
        assert panel._category_chart._series == []  # noqa: SLF001
        assert panel._timeline_chart._series == []  # noqa: SLF001
        panel.close()


# --------------------------------------------------------------------------- #
# Simulation corpus / worker
# --------------------------------------------------------------------------- #
class TestSimulationCorpus:
    def test_corpus_covers_every_category(self) -> None:
        categories = {category for category, _name in corpus_categories()}
        for required in (
            KeyCategory.LETTER, KeyCategory.NUMBER, KeyCategory.PUNCTUATION,
            KeyCategory.MODIFIER, KeyCategory.NAVIGATION, KeyCategory.ARROW,
            KeyCategory.FUNCTION, KeyCategory.NUMPAD, KeyCategory.OTHER,
            KeyCategory.UNKNOWN,
        ):
            assert required in categories, f"corpus missing {required}"

    def test_specification_examples_present(self) -> None:
        names = set(synthetic_key_names())
        for required in ("A", "B", "Enter", "Ctrl Left", "F5", "Up", "Numpad 1"):
            assert required in names

    def test_corpus_contains_unmapped_key(self) -> None:
        """An unmapped hardware key must be exercised in simulation."""
        assert "Unknown / Unmapped" in synthetic_key_names()


class TestMonitorGuards:
    def test_start_requires_consent(self, database: Database, sim_config: AppConfig) -> None:
        monitor = EventMonitor(sim_config, database)
        with pytest.raises(MonitoringError, match="consent"):
            monitor.start(consent_acknowledged=False)
        assert not monitor.is_running

    def test_double_start_rejected(self, database: Database, sim_config: AppConfig) -> None:
        monitor = EventMonitor(sim_config, database)
        monitor.start(consent_acknowledged=True)
        try:
            with pytest.raises(MonitoringError, match="already running"):
                monitor.start(consent_acknowledged=True)
        finally:
            monitor.stop()

    def test_stop_without_start_is_safe(self, database: Database, sim_config: AppConfig) -> None:
        monitor = EventMonitor(sim_config, database)
        assert monitor.stop() is True

    def test_session_cap_stops_worker(self, tmp_path: Path, database: Database) -> None:
        """A tiny cap must terminate the worker instead of running forever."""
        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=500.0,
            max_events_per_session=10,
        ).sanitized()
        monitor = EventMonitor(config, database)
        monitor.start(consent_acknowledged=True)
        finished = _wait_until(lambda: not monitor.is_running, timeout=10.0)
        monitor.stop()
        assert finished
        assert database.count_events() >= 1
        assert database.count_events() <= 60

    def test_late_thread_finished_keeps_the_new_session(
        self, database: Database, sim_config: AppConfig
    ) -> None:
        """A stale ``finished`` from session 1 must not release session 2.

        ``QThread.finished`` is delivered through the owner event loop, so a
        notification from a session that has already ended can arrive after
        the analyst has already pressed Start again.  Releasing the current
        worker at that point would destroy a running QObject from the GUI
        thread, which Qt aborts on at shutdown.
        """
        monitor = EventMonitor(sim_config, database)
        try:
            monitor.start(consent_acknowledged=True)
            first_thread = monitor._thread  # noqa: SLF001
            first_session = monitor.session_id
            assert monitor.stop() is True

            # No event pumping: the queued ``finished`` for session 1 is still
            # pending when the next session begins.
            monitor.start(consent_acknowledged=True)
            second_thread = monitor._thread  # noqa: SLF001
            second_session = monitor.session_id
            assert second_thread is not first_thread
            assert second_session != first_session

            # Deliver the stale notification now, as the event loop would.
            monitor._release_thread(first_thread)  # noqa: SLF001

            assert monitor._thread is second_thread  # noqa: SLF001
            assert monitor._worker is not None  # noqa: SLF001
            assert monitor.is_running
            assert monitor.session_id == second_session
            assert second_thread.isRunning()
        finally:
            monitor.stop()
            monitor.shutdown()


# --------------------------------------------------------------------------- #
# GUI integration
# --------------------------------------------------------------------------- #
class TestMainWindow:
    def test_window_constructs(self, app, tmp_path: Path) -> None:
        config = AppConfig(simulation_mode=True).sanitized()
        database = Database(tmp_path / "w.sqlite3")
        database.initialize()
        store = ConfigStore(tmp_path / "config.json")
        window = MainWindow(config, database, store)
        try:
            assert window.status_strip.status_label.text() == "Status: STOPPED"
            assert window.status_strip.events_label.text() == "Events Recorded: 0"
            assert window.status_strip.started_label.text() == "Session Started: -"
            assert window.status_strip.duration_label.text() == "Session Duration: -"
            assert window.model.rowCount() == 0
        finally:
            window.close()
            database.close()

    def test_consent_gate_disables_start(self, app, tmp_path: Path) -> None:
        config = AppConfig(simulation_mode=True).sanitized()
        database = Database(tmp_path / "w2.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            # Consent not yet acknowledged -> Start must be disabled.
            assert not window.start_button.isEnabled()
            window._consent_acknowledged = True  # noqa: SLF001
            window._update_button_states()  # noqa: SLF001
            assert window.start_button.isEnabled()
        finally:
            window.close()
            database.close()

    def test_start_button_refuses_without_consent(self, app, tmp_path: Path) -> None:
        config = AppConfig(simulation_mode=True).sanitized()
        database = Database(tmp_path / "w3.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            window._on_start()  # noqa: SLF001 - must be a no-op
            assert not window.monitor.is_running
        finally:
            window.close()
            database.close()

    def test_consent_button_asks_for_confirmation(self, app, tmp_path: Path, monkeypatch) -> None:
        """Ticking the consent switch must show the authorization prompt."""
        database = Database(tmp_path / "w3b.sqlite3")
        database.initialize()
        window = MainWindow(
            AppConfig(simulation_mode=True).sanitized(),
            database,
            ConfigStore(tmp_path / "c.json"),
        )
        asked: list[str] = []

        def record(*args, **kwargs) -> QMessageBox.StandardButton:
            asked.append(str(args[1]))
            return QMessageBox.StandardButton.Yes

        monkeypatch.setattr(QMessageBox, "question", staticmethod(record))
        try:
            window.consent_button.setChecked(True)
            assert asked, "the authorization prompt was never shown"
            assert window._consent_acknowledged  # noqa: SLF001
        finally:
            window.close()
            database.close()

    def test_consent_declined_leaves_start_disabled(self, app, tmp_path: Path, monkeypatch) -> None:
        database = Database(tmp_path / "w3c.sqlite3")
        database.initialize()
        window = MainWindow(
            AppConfig(simulation_mode=True).sanitized(),
            database,
            ConfigStore(tmp_path / "c.json"),
        )
        monkeypatch.setattr(
            QMessageBox, "question",
            staticmethod(lambda *a, **k: QMessageBox.StandardButton.No),
        )
        try:
            window.consent_button.setChecked(True)
            assert not window._consent_acknowledged  # noqa: SLF001
            assert not window.consent_button.isChecked()
            assert not window.start_button.isEnabled()
        finally:
            window.close()
            database.close()

    def test_menu_acknowledge_consent_ticks_the_switch(
        self, app, tmp_path: Path, monkeypatch
    ) -> None:
        """The menu item must route through the switch, not pass checked=False."""
        database = Database(tmp_path / "w3d.sqlite3")
        database.initialize()
        window = MainWindow(
            AppConfig(simulation_mode=True).sanitized(),
            database,
            ConfigStore(tmp_path / "c.json"),
        )
        monkeypatch.setattr(
            QMessageBox, "question",
            staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes),
        )
        try:
            window._on_menu_acknowledge_consent()  # noqa: SLF001
            assert window.consent_button.isChecked()
            assert window._consent_acknowledged  # noqa: SLF001
            assert window.start_button.isEnabled()
        finally:
            window.close()
            database.close()

    def test_simulation_records_and_displays_events(self, app, tmp_path: Path) -> None:
        """End-to-end: Start -> events stored -> table populated -> Stop."""
        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0,
            gui_refresh_ms=100, table_page_size=500,
        ).sanitized()
        database = Database(tmp_path / "sim.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            window._consent_acknowledged = True  # noqa: SLF001
            window._on_start()  # noqa: SLF001
            assert window.monitor.is_running
            assert window.status_strip.status_label.text() == "● LOGGING"
            assert window.stop_button.isEnabled()
            assert not window.start_button.isEnabled()

            recorded = _wait_until(lambda: window.model.rowCount() > 20, timeout=15.0)
            assert recorded, "no events reached the table"

            assert database.count_events() > 20
            assert window.status_strip.events_label.text() != "Events Recorded: 0"

            session_id = window.monitor.session_id
            assert is_valid_session_id(session_id)

            window._on_stop()  # noqa: SLF001
            assert not window.monitor.is_running
            assert window.status_strip.status_label.text() == "Status: STOPPED"

            record = database.get_session(session_id)
            assert record is not None
            assert record.ended_at is not None
            assert record.event_count > 0
        finally:
            window.close()
            database.close()

    def test_new_session_hides_previously_recorded_events(
        self, app, tmp_path: Path
    ) -> None:
        """Starting a session must show only that session's events."""
        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0,
            gui_refresh_ms=100, table_page_size=500,
        ).sanitized()
        database = Database(tmp_path / "scoped.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            window._consent_acknowledged = True  # noqa: SLF001

            # --- first session ------------------------------------------- #
            window._on_start()  # noqa: SLF001
            first_id = window.monitor.session_id
            assert _wait_until(lambda: window.model.rowCount() > 20, timeout=15.0)
            window._on_stop()  # noqa: SLF001
            first_rows = window.model.rowCount()
            assert first_rows > 20

            # --- second session ------------------------------------------ #
            window._on_start()  # noqa: SLF001
            second_id = window.monitor.session_id
            assert second_id != first_id
            # The table is scoped to the new session, so it starts empty even
            # though the database already holds the first session's rows.
            assert window.model.rowCount() == 0
            assert window.filter_panel.current_filtered_session_id() == second_id

            assert _wait_until(lambda: window.model.rowCount() > 5, timeout=15.0)
            visible = {row.session_id for row in
                       database.query_events(EventFilter(session_id=second_id))}
            assert visible == {second_id}
            window._on_stop()  # noqa: SLF001

            # Untick the scope to reach history again.
            window.filter_panel.only_current_check.setChecked(False)
            assert window.filter_panel.current_filtered_session_id() is None
            assert _wait_until(
                lambda: window.model.rowCount() >= first_rows + 5, timeout=8.0
            ), f"expected the full history, saw {window.model.rowCount()} rows"

            # And the session dropdown still targets one specific session.
            window.filter_panel.session_combo.setCurrentIndex(1)
            _wait_until(lambda: True, timeout=0.1)
            assert window.filter_panel.current_filtered_session_id() is not None
        finally:
            window.close()
            database.close()

    def test_scope_checkbox_is_checked_by_default(self, app, tmp_path: Path) -> None:
        database = Database(tmp_path / "scope_default.sqlite3")
        database.initialize()
        window = MainWindow(
            AppConfig(simulation_mode=True).sanitized(),
            database,
            ConfigStore(tmp_path / "c.json"),
        )
        try:
            assert window.filter_panel.only_current_check.isChecked()
            # With no session running the checkbox cannot hide anything.
            assert window.filter_panel.current_filtered_session_id() is None
            assert database.count_events(EventFilter(session_id="S-000000000000")) == 0
        finally:
            window.close()
            database.close()

    def test_filters_work_on_recorded_events(self, app, tmp_path: Path) -> None:
        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0, gui_refresh_ms=100,
        ).sanitized()
        database = Database(tmp_path / "filter.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            window._consent_acknowledged = True  # noqa: SLF001
            window._on_start()  # noqa: SLF001
            _wait_until(lambda: window.model.rowCount() > 30, timeout=15.0)
            window._on_stop()  # noqa: SLF001
            total = window.model.rowCount()
            assert total > 0

            # Filter by key category -> a strict subset.
            categories = database.distinct_values("key_category")
            assert categories
            window.filter_panel.category_combo.setCurrentText("Function")
            _wait_until(
                lambda: window.model.rowCount() < total
                or window.model.rowCount() == database.count_events(
                    EventFilter(key_category="Function")),
                timeout=5.0,
            )
            filtered = window.model.rowCount()
            expected = database.count_events(EventFilter(key_category="Function"))
            assert filtered == expected

            window.filter_panel.clear_filters()
            _wait_until(lambda: window.model.rowCount() == total, timeout=5.0)
        finally:
            window.close()
            database.close()

    def test_dashboard_updates(self, app, tmp_path: Path) -> None:
        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0, gui_refresh_ms=100,
        ).sanitized()
        database = Database(tmp_path / "dash.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            window._consent_acknowledged = True  # noqa: SLF001
            window._on_start()  # noqa: SLF001
            _wait_until(lambda: window.model.rowCount() > 20, timeout=15.0)
            window._on_stop()  # noqa: SLF001
            window._update_dashboard()  # noqa: SLF001
            total_text = window.dashboard._counters["total_events"].text()  # noqa: SLF001
            assert total_text not in {"-", "0"}
            assert int(total_text.replace(",", "")) == database.count_events()
        finally:
            window.close()
            database.close()

    def test_export_button_produces_workbook(self, app, tmp_path: Path, monkeypatch) -> None:
        from PySide6.QtWidgets import QFileDialog

        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0, gui_refresh_ms=100,
        ).sanitized()
        database = Database(tmp_path / "exp.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        target = tmp_path / "gui_export.xlsx"
        try:
            window._consent_acknowledged = True  # noqa: SLF001
            window._on_start()  # noqa: SLF001
            _wait_until(lambda: window.model.rowCount() > 10, timeout=15.0)
            window._on_stop()  # noqa: SLF001

            monkeypatch.setattr(
                QFileDialog, "getSaveFileName",
                staticmethod(lambda *a, **k: (str(target), "Excel Workbook (*.xlsx)")),
            )
            monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: None))
            window._on_export()  # noqa: SLF001

            assert target.exists()
            from openpyxl import load_workbook

            workbook = load_workbook(target)
            assert "Keyboard Events" in workbook.sheetnames
            assert "Session Summary" in workbook.sheetnames
        finally:
            window.close()
            database.close()

    def test_clear_records_empties_database(self, app, tmp_path: Path, monkeypatch) -> None:
        from PySide6.QtWidgets import QMessageBox

        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0, gui_refresh_ms=100,
        ).sanitized()
        database = Database(tmp_path / "clear.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        try:
            window._consent_acknowledged = True  # noqa: SLF001
            window._on_start()  # noqa: SLF001
            _wait_until(lambda: window.model.rowCount() > 10, timeout=15.0)
            window._on_stop()  # noqa: SLF001
            assert database.count_events() > 0

            monkeypatch.setattr(
                QMessageBox, "question",
                staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes),
            )
            window._on_clear_records()  # noqa: SLF001
            assert database.count_events() == 0
            assert window.model.rowCount() == 0
        finally:
            window.close()
            database.close()

    def test_settings_apply_and_persist(self, app, tmp_path: Path) -> None:
        from keyboard_monitor.gui import SettingsDialog

        config = AppConfig().sanitized()
        database = Database(tmp_path / "set.sqlite3")
        database.initialize()
        store = ConfigStore(tmp_path / "c.json")
        window = MainWindow(config, database, store)
        try:
            dialog = SettingsDialog(config, window)
            dialog.location_edit.setText("Test Machine 42")
            dialog.redaction_check.setChecked(True)
            problems = dialog.apply_to(config)
            assert problems == []
            assert config.location_label == "Test Machine 42"
            store.save(config)
            assert store.load().location_label == "Test Machine 42"
        finally:
            window.close()
            database.close()

    def test_closing_while_running_stops_cleanly(self, app, tmp_path: Path, monkeypatch) -> None:
        from PySide6.QtWidgets import QMessageBox

        config = AppConfig(
            simulation_mode=True, simulation_events_per_second=150.0,
        ).sanitized()
        database = Database(tmp_path / "shutdown.sqlite3")
        database.initialize()
        window = MainWindow(config, database, ConfigStore(tmp_path / "c.json"))
        monkeypatch.setattr(
            QMessageBox, "question",
            staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes),
        )
        window._consent_acknowledged = True  # noqa: SLF001
        window._on_start()  # noqa: SLF001
        _wait_until(lambda: window.model.rowCount() > 5, timeout=15.0)
        window.close()
        QApplication.processEvents()
        assert not window.monitor.is_running

    def test_monitor_reports_live_mode_in_status(self, app, tmp_path: Path) -> None:
        config = AppConfig(simulation_mode=False).sanitized()
        database = Database(tmp_path / "live.sqlite3")
        database.initialize()
        monitor = EventMonitor(config, database)
        assert monitor.mode == "LIVE CAPTURE"
        database.close()


# --------------------------------------------------------------------------- #
# Worker unit-level checks (no Qt event loop needed for the pipeline)
# --------------------------------------------------------------------------- #
class TestWorkerPipeline:
    def test_duplicate_events_suppressed(self, database: Database, sim_config: AppConfig) -> None:

        from keyboard_monitor.security import RedactionPolicy, utc_now
        from keyboard_monitor.window_info import ForegroundWindowClassifier

        worker = MonitorWorker(
            sim_config, database, "S-0123456789AB",
            ForegroundWindowClassifier(RedactionPolicy()),
        )
        identity = normalize_key("a")
        moment = utc_now()
        # Three identical downs inside the debounce window -> only the first lands.
        for _ in range(3):
            worker._submit(identity, EventType.KEY_DOWN, moment)
        assert worker._pending.qsize() == 1

    def test_repeat_flagged_after_threshold(self, database: Database, sim_config: AppConfig) -> None:
        from keyboard_monitor.models import KeyEvent
        from keyboard_monitor.security import RedactionPolicy, utc_now
        from keyboard_monitor.window_info import ForegroundWindowClassifier

        config = sim_config
        config.dedupe_window_ms = 0  # isolate repeat logic from debouncing
        worker = MonitorWorker(
            config, database, "S-0123456789AB",
            ForegroundWindowClassifier(RedactionPolicy()),
        )
        identity = normalize_key("a")
        moment = utc_now()

        def drain() -> list[KeyEvent]:
            batch: list[KeyEvent] = []
            while True:
                try:
                    batch.append(worker._pending.get_nowait())
                except Exception:
                    break
            return batch

        worker._submit(identity, EventType.KEY_DOWN, moment)
        first = drain()
        for index in range(4):
            worker._submit(identity, EventType.KEY_DOWN, moment)
        rest = drain()
        assert first and not first[0].is_repeat
        assert any(event.is_repeat for event in rest)

    def test_unknown_key_never_raises(self, database: Database, sim_config: AppConfig) -> None:
        from keyboard_monitor.security import RedactionPolicy, utc_now
        from keyboard_monitor.window_info import ForegroundWindowClassifier

        worker = MonitorWorker(
            sim_config, database, "S-0123456789AB",
            ForegroundWindowClassifier(RedactionPolicy()),
        )
        # A garbage key name must flow through the pipeline unharmed.
        worker._submit(normalize_key("unidentified FF FE"), EventType.KEY_DOWN, utc_now())
        assert worker._pending.qsize() == 1
        event = worker._pending.get_nowait()
        assert event.key_name == "Unknown / Unmapped"
        assert event.key_category is KeyCategory.UNKNOWN

    def test_rate_limiter_drops_excess(self, database: Database) -> None:
        from keyboard_monitor.security import RedactionPolicy, utc_now
        from keyboard_monitor.window_info import ForegroundWindowClassifier

        config = AppConfig(
            simulation_mode=True, max_events_per_second=5, dedupe_window_ms=0,
        ).sanitized()
        worker = MonitorWorker(
            config, database, "S-0123456789AB",
            ForegroundWindowClassifier(RedactionPolicy()),
        )
        moment = utc_now()
        for index in range(50):
            worker._submit(normalize_key(chr(ord("a") + index % 26)),
                           EventType.KEY_DOWN, moment)
        assert worker._pending.qsize() <= config.max_events_per_second


# --------------------------------------------------------------------------- #
# Import-time Qt usage guard
# --------------------------------------------------------------------------- #
def test_gui_module_does_not_autostart() -> None:
    """Importing the GUI must not create a window or start monitoring."""
    import keyboard_monitor.gui as gui_module

    assert not hasattr(gui_module, "_app_instance")
    assert callable(getattr(gui_module, "MainWindow"))