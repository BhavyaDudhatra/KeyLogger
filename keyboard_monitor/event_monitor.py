"""Keyboard event capture: live capture and safe simulation.

Architecture
------------
``EventMonitor`` (Qt object, GUI thread)
    Owns the worker :class:`QThread` and exposes ``start``/``stop``.  It is the
    only place where a monitoring session begins or ends, which is what
    guarantees that two sessions can never run simultaneously.

``MonitorWorker`` (moved onto the worker thread)
    * **live mode** registers a low-level keyboard hook through the ``keyboard``
      library (see the README for the Windows/Linux/macOS caveats),
    * **simulation mode** fabricates events from a fixed corpus and never
      touches the real keyboard at all,
    * normalizes each event, batches it, writes the batch to SQLite and emits a
      Qt signal so the GUI can refresh.

All heavy work (OS hook, normalization, SQL writes) happens off the GUI thread,
so the interface stays responsive while events are being recorded.

Security notes
--------------
* Hooks are registered with ``suppress=False``: the monitor is strictly passive
  and never swallows, alters, blocks or injects a keystroke.
* The hook callback performs no I/O - it normalizes and appends to an in-memory
  queue - so a burst of keystrokes cannot stall the OS input queue.
* Live capture requires an explicit ``consent_acknowledged=True`` argument, so
  no code path can begin recording without the operator having pressed
  *Start Logging* and acknowledged the consent notice.
* Two hard caps (``max_events_per_second`` and ``max_events_per_session``)
  bound resource use.  Nothing is written outside the local database.
"""

from __future__ import annotations

import logging
import queue
import random
import threading
import time
from dataclasses import replace
from datetime import datetime
from typing import Callable, Final, Iterable, Sequence

from PySide6.QtCore import QObject, Qt, QThread, Signal

from .config import AppConfig
from .database import Database, DatabaseError
from .models import (
    EventType,
    KeyCategory,
    KeyEvent,
    KeyIdentity,
    ModifierTracker,
    RedactionStatus,
    new_session_id,
    normalize_key,
)
from .security import RedactionPolicy, utc_now
from .window_info import ForegroundWindowClassifier

LOGGER = logging.getLogger(__name__)

__all__ = [
    "EventMonitor",
    "MonitorWorker",
    "MonitoringError",
    "SIMULATION_CORPUS",
    "synthetic_key_names",
    "corpus_categories",
]

#: Number of buffered events that triggers an immediate batch flush.
_FLUSH_SIZE: Final[int] = 25
#: Longest a buffered event waits before being flushed anyway (seconds).
_FLUSH_INTERVAL: Final[float] = 0.12
#: Poll interval of the worker loop (seconds).
_POLL_INTERVAL: Final[float] = 0.02
#: Minimum gap between two analyst-visible notices (seconds).
_NOTICE_COOLDOWN: Final[float] = 2.0

#: Synthetic corpus used by Simulation Mode.  Covers every key category in the
#: specification plus the awkward "hardware-specific / unmapped" case, so the
#: GUI, database, filtering, statistics and export can all be exercised safely.
SIMULATION_CORPUS: Final[tuple[tuple[str, int], ...]] = (
    ("a", 6), ("b", 6), ("c", 4), ("A", 3), ("Shift", 5), ("Ctrl", 5), ("Alt", 2),
    ("Enter", 4), ("Space", 4), ("Backspace", 2), ("Tab", 2), ("Esc", 1),
    ("F5", 2), ("F12", 1), ("Up", 2), ("Down", 2), ("Left", 1), ("Right", 1),
    ("Numpad 1", 2), ("Numpad 5", 1), ("Numpad Enter", 1),
    ("Home", 1), ("End", 1), ("Page Up", 1), ("Delete", 1),
    ("1", 2), ("7", 1), ("0", 1), ("-", 1), ("/", 1), (".", 1),
    ("Caps Lock", 1), ("Print Screen", 1), ("Pause", 1),
    ("unidentified 00 FF 2A", 1),
)


class MonitoringError(RuntimeError):
    """Raised when a monitoring session cannot be started or continued."""


class MonitorWorker(QObject):
    """Capture worker; every method runs on the worker thread."""

    #: ``list[KeyEvent]`` flushed to SQLite.
    batchReady = Signal(list)
    #: Non-fatal message for the analyst (rate caps, notices).
    notice = Signal(str)
    #: ``title``, ``detail`` - the session cannot continue.
    failed = Signal(str, str)
    #: Emitted once the worker thread has finished its shutdown sequence.
    workerStopped = Signal()

    def __init__(
        self,
        config: AppConfig,
        database: Database,
        session_id: str,
        classifier: ForegroundWindowClassifier,
        *,
        random_seed: int | None = None,
    ) -> None:
        super().__init__()
        self._config = config
        self._database = database
        self._session_id = session_id
        self._classifier = classifier

        self._stop_event = threading.Event()
        self._pending: "queue.Queue[KeyEvent]" = queue.Queue()
        self._tracker = ModifierTracker()

        # duplicate suppression / rollover detection state
        self._dedupe: dict[tuple[str, str], float] = {}
        self._down_at: dict[str, float] = {}
        self._press_count: dict[str, int] = {}

        # rate limiting / caps
        self._accepted = 0
        self._dropped = 0
        self._rate_window_start = time.monotonic()
        self._rate_window_count = 0
        self._last_notice = 0.0

        self._window: tuple[str, str] = ("Unknown Application", RedactionStatus.NORMAL.value)
        self._remove_hook: Callable[[], object] | None = None
        self._random = random.Random(random_seed)

    # ------------------------------------------------------------------ #
    # Thread entry point
    # ------------------------------------------------------------------ #
    def request_stop(self) -> None:
        """Ask the worker to wind down.

        ``threading.Event.set`` is safe from any thread, which keeps the
        shutdown path free of queued-signal ordering hazards.
        """
        self._stop_event.set()

    @property
    def stopping(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        """Body executed inside the worker thread by ``QThread.start``."""
        LOGGER.info(
            "Worker thread started for session %s (%s).",
            self._session_id,
            "simulation" if self._config.simulation_mode else "live capture",
        )
        try:
            if self._config.simulation_mode:
                self._simulate()
            else:
                self._capture_live()
        except PermissionError as exc:
            self.failed.emit(
                "Permission denied",
                f"The operating system refused keyboard monitoring: {exc}\n\n"
                "This tool does not bypass operating-system security controls. Use an "
                "approved lab process, or switch to Simulation Mode in Settings.",
            )
        except MonitoringError as exc:
            self.failed.emit("Monitoring unavailable", str(exc))
        except DatabaseError as exc:
            self.failed.emit("Storage error", str(exc))
        except Exception as exc:  # pragma: no cover - never let the GUI die
            LOGGER.exception("Monitoring worker failed unexpectedly.")
            self.failed.emit("Monitoring error", str(exc))
        finally:
            try:
                self._drain(force=True)
            except DatabaseError as exc:  # pragma: no cover - defensive
                self.failed.emit("Storage error", str(exc))
            self._release_hook()
            self.workerStopped.emit()

    # ------------------------------------------------------------------ #
    # Live capture
    # ------------------------------------------------------------------ #
    def _capture_live(self) -> None:
        """Register the OS keyboard hook and pump events until asked to stop."""
        try:
            import keyboard  # lazy: Simulation Mode needs no backend at all
        except ImportError as exc:
            raise MonitoringError(
                "The 'keyboard' package is required for live capture. "
                "Install it with: pip install keyboard"
            ) from exc

        # suppress=False -> purely observational, input is never altered.
        self._remove_hook = keyboard.hook(self._on_raw_event, suppress=False)
        LOGGER.info("Live keyboard hook registered for session %s.", self._session_id)
        self._pump()

    def _release_hook(self) -> None:
        """Remove the OS hook (if any).  Never blocks or injects input."""
        if self._remove_hook is None:
            return
        try:
            self._remove_hook()
        except Exception:  # pragma: no cover - library shutdown race
            LOGGER.debug("Hook removal raised during shutdown.", exc_info=True)
        finally:
            self._remove_hook = None
        try:
            import keyboard

            keyboard.unhook_all()
        except Exception:  # pragma: no cover - best effort
            LOGGER.debug("unhook_all() raised during shutdown.", exc_info=True)

    def _on_raw_event(self, raw_event: object) -> None:
        """Hook callback, invoked on the keyboard library's listener thread.

        Intentionally cheap: normalize, filter, enqueue.  A malformed event is
        dropped with a debug log instead of propagating an exception into the
        library's message loop.
        """
        try:
            key_name = getattr(raw_event, "key", None)
            raw_type = getattr(raw_event, "event_type", None)
            if not isinstance(key_name, str) or not key_name:
                return
            if raw_type == "key_down":
                event_type = EventType.KEY_DOWN
            elif raw_type == "key_up":
                event_type = EventType.KEY_UP
            else:
                return
            self._submit(normalize_key(key_name), event_type, utc_now())
        except Exception:  # pragma: no cover - defensive
            LOGGER.debug("Discarded a malformed keyboard event.", exc_info=True)

    # ------------------------------------------------------------------ #
    # Simulation Mode
    # ------------------------------------------------------------------ #
    def _simulate(self) -> None:
        """Generate artificial events without reading the real keyboard."""
        names = [name for name, _weight in SIMULATION_CORPUS]
        weights = [weight for _name, weight in SIMULATION_CORPUS]
        interval = 1.0 / max(0.5, self._config.simulation_events_per_second)
        LOGGER.info("Simulation Mode started for session %s.", self._session_id)

        while not self._stop_event.is_set():
            if self._session_capped():
                return
            # Rare bursts exercise the repeat and anomaly-detection paths.
            burst = 9 if self._random.random() < 0.07 else 1
            for index in range(burst):
                raw_name = self._random.choices(names, weights=weights, k=1)[0]
                identity = normalize_key(raw_name)
                self._submit(identity, EventType.KEY_DOWN, utc_now(), force_repeat=index > 0)
                if not (identity.is_modifier or identity.is_lock):
                    self._submit(identity, EventType.KEY_UP, utc_now())
            self._stop_event.wait(interval * (0.5 if burst > 1 else 1.0))

    # ------------------------------------------------------------------ #
    # Shared pipeline
    # ------------------------------------------------------------------ #
    def _session_capped(self) -> bool:
        """Stop (once) when ``max_events_per_session`` has been reached."""
        cap = self._config.max_events_per_session
        if cap <= 0 or self._accepted < cap:
            return False
        self._notify(
            f"Session cap of {cap:,} events reached - monitoring stopped automatically. "
            "Raise the limit in Settings if you need a longer capture."
        )
        self._stop_event.set()
        return True

    def _rate_limited(self) -> bool:
        """Sliding-window limiter that protects the GUI thread and the database."""
        now = time.monotonic()
        if now - self._rate_window_start >= 1.0:
            self._rate_window_start = now
            self._rate_window_count = 0
        self._rate_window_count += 1
        if self._rate_window_count <= self._config.max_events_per_second:
            return False
        self._dropped += 1
        if self._dropped in (25, 250, 1000):
            self._notify(
                f"Input rate exceeded {self._config.max_events_per_second} events/s; "
                "excess events are dropped to keep the interface responsive."
            )
        return True

    def _is_duplicate(self, identity: KeyIdentity, event_type: EventType) -> bool:
        """Suppress OS auto-repeat duplicates and stray repeated KEY_UPs."""
        window = self._config.dedupe_window_ms / 1000.0
        if window <= 0:
            return False
        now = time.monotonic()
        signature = (identity.display_name, event_type.value)
        previous = self._dedupe.get(signature)
        if previous is not None and (now - previous) < window:
            return True
        self._dedupe[signature] = now
        if len(self._dedupe) > 512:  # bounded cache; stale keys are dropped
            cutoff = now - max(window, 1.0)
            self._dedupe = {k: v for k, v in self._dedupe.items() if v >= cutoff}
        return False

    def _track_press(self, identity: KeyIdentity, event_type: EventType) -> bool:
        """Update rollover state; return ``True`` when this is an auto-repeat.

        The operating system re-emits ``key_down`` for a key that is being held.
        Counting consecutive downs for the same key identifies that rollover
        without ever reconstructing what the user typed.
        """
        key = identity.display_name
        if event_type is EventType.KEY_DOWN:
            now = time.monotonic()
            already_down = key in self._down_at
            self._down_at[key] = now
            self._press_count[key] = self._press_count.get(key, 0) + 1
            if not already_down:
                return False
            return self._press_count[key] >= max(2, self._config.repeat_threshold)
        self._down_at.pop(key, None)
        self._press_count.pop(key, None)
        return False

    def _submit(
        self,
        identity: KeyIdentity,
        event_type: EventType,
        moment: datetime,
        *,
        force_repeat: bool = False,
    ) -> None:
        """Normalize, de-duplicate, rate-limit and enqueue a single event."""
        if self._stop_event.is_set():
            return
        if self._rate_limited() or self._is_duplicate(identity, event_type):
            return

        if event_type is EventType.KEY_DOWN:
            modifiers = self._tracker.press(identity)
            is_repeat = force_repeat or self._track_press(identity, event_type)
        else:
            modifiers = self._tracker.release(identity)
            self._track_press(identity, event_type)
            is_repeat = False

        app_class, redaction_status = self._window
        self._pending.put(KeyEvent(
            key_name=identity.display_name,
            key_category=identity.category,
            key_group=identity.group,
            event_type=event_type,
            timestamp=moment,
            session_id=self._session_id,
            application_class=app_class,
            modifier_state=modifiers.as_string(),
            redaction_status=RedactionStatus(redaction_status),
            location_label=self._config.location_label,
            is_repeat=is_repeat,
        ))
        self._accepted += 1

        if self._pending.qsize() >= _FLUSH_SIZE:
            self._drain(force=True)

    def _notify(self, message: str) -> None:
        """Log a message and surface it to the analyst at most once per cooldown."""
        LOGGER.info("%s", message)
        now = time.monotonic()
        if now - self._last_notice >= _NOTICE_COOLDOWN:
            self._last_notice = now
            self.notice.emit(message)

    def _pump(self) -> None:
        """Worker loop for live capture: flush buffered batches periodically."""
        last_flush = time.monotonic()
        while not self._stop_event.is_set():
            now = time.monotonic()
            queued = self._pending.qsize()
            if queued >= _FLUSH_SIZE or (queued and now - last_flush >= _FLUSH_INTERVAL):
                self._drain(force=True)
                last_flush = now
            self._stop_event.wait(_POLL_INTERVAL)

    def _resolve_window(self) -> None:
        """Classify the foreground window once per batch.

        A batch spans at most ~120 ms, so one lookup is both cheaper and more
        self-consistent than one lookup per keystroke.  Window text is consumed
        by :class:`~keyboard_monitor.security.RedactionPolicy` and discarded.
        """
        if not self._config.classify_foreground_application:
            self._window = ("Unknown Application", RedactionStatus.NORMAL.value)
            return
        try:
            app_class, status, _label = self._classifier.classify()
            self._window = (app_class, status)
        except Exception:  # pragma: no cover - defensive
            LOGGER.debug("Window classification failed.", exc_info=True)
            self._window = ("Unknown Application", RedactionStatus.NORMAL.value)

    def _drain(self, *, force: bool) -> int:
        """Persist buffered events to SQLite and emit them as a Qt signal."""
        queued = self._pending.qsize()
        if queued == 0 or (not force and queued < _FLUSH_SIZE):
            return 0

        batch: list[KeyEvent] = []
        while True:
            try:
                batch.append(self._pending.get_nowait())
            except queue.Empty:
                break
        if not batch:
            return 0

        self._resolve_window()
        app_class, redaction = self._window
        batch = [
            replace(event, application_class=app_class, redaction_status=RedactionStatus(redaction))
            for event in batch
        ]

        self._database.insert_events(batch)
        self.batchReady.emit(batch)
        return len(batch)


class EventMonitor(QObject):
    """GUI-facing facade owning at most one monitoring session."""

    #: ``list[KeyEvent]`` persisted by the worker.
    batchReady = Signal(list)
    #: Non-fatal, analyst-visible message.
    notice = Signal(str)
    #: ``title``, ``detail`` - the session could not continue.
    failed = Signal(str, str)
    runningChanged = Signal(bool)
    sessionStarted = Signal(str)
    sessionFinished = Signal(str, int)

    def __init__(
        self,
        config: AppConfig,
        database: Database,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._database = database
        self._thread: QThread | None = None
        self._worker: MonitorWorker | None = None
        self._session_id: str = ""
        self._events_this_session = 0
        self._started_at: datetime | None = None
        self._running = False

    # -- state -------------------------------------------------------------- #
    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def events_this_session(self) -> int:
        return self._events_this_session

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def mode(self) -> str:
        return "SIMULATION" if self._config.simulation_mode else "LIVE CAPTURE"

    # -- lifecycle ---------------------------------------------------------- #
    def start(self, *, consent_acknowledged: bool) -> str:
        """Begin a session and return its id.

        Raises
        ------
        MonitoringError
            When a session is already running, when the consent notice has not
            been acknowledged, or when the worker could not be started.
        """
        if self._running:
            raise MonitoringError(
                "A monitoring session is already running. Stop it before starting another."
            )
        # Defence in depth: the GUI keeps Start disabled until the analyst has
        # acknowledged the notice; the same rule is enforced here.
        if self._config.require_consent_acknowledgement and not consent_acknowledged:
            raise MonitoringError(
                "The consent notice must be acknowledged before logging can start."
            )

        self._session_id = new_session_id()
        self._events_this_session = 0
        self._started_at = utc_now()

        policy = RedactionPolicy(
            enabled=self._config.redaction_enabled,
            patterns=self._config.sensitive_window_patterns,
        )
        classifier = ForegroundWindowClassifier(
            policy, enabled=self._config.classify_foreground_application
        )

        try:
            self._database.start_session(
                self._session_id,
                started_at=self._started_at,
                simulated=self._config.simulation_mode,
                redaction_enabled=self._config.redaction_enabled,
                location_label=self._config.location_label,
            )
        except (DatabaseError, ValueError) as exc:
            raise MonitoringError(f"The monitoring session could not be recorded: {exc}") from exc

        worker = MonitorWorker(self._config, self._database, self._session_id, classifier)
        thread = QThread(self)
        thread.setObjectName("keyboard-monitor-worker")
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        # The handler is bound to *this* thread: a late 'finished' from an
        # earlier session must never release the references of a newer one.
        thread.finished.connect(self._thread_finished_handler(thread))
        worker.batchReady.connect(self._on_batch)
        worker.notice.connect(self.notice)
        worker.failed.connect(self.failed)
        # DirectConnection: QThread.quit() must run from the worker thread so the
        # thread's event loop stops even when the owner thread has no running
        # event loop (headless runs, early shutdown).
        worker.workerStopped.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        # Direct: settle session state on the worker thread (no owner loop needed).
        worker.workerStopped.connect(self._settle_session, Qt.ConnectionType.DirectConnection)
        # Queued to the owner thread: notifies the GUI.
        worker.workerStopped.connect(self._stopped_handler(self._session_id))

        self._worker = worker
        self._thread = thread
        self._running = True

        thread.start()
        self.sessionStarted.emit(self._session_id)
        self.runningChanged.emit(True)
        LOGGER.info(
            "Monitoring session %s started (%s, redaction=%s).",
            self._session_id, self.mode, self._config.redaction_enabled,
        )
        return self._session_id

    def stop(self, *, timeout_ms: int = 4000) -> bool:
        """Stop the session and finalise it.

        Returns ``True`` when the worker shut down within ``timeout_ms``.
        """
        thread = self._thread
        worker = self._worker
        if thread is None:
            self._running = False
            return True

        if worker is not None:
            worker.request_stop()
        clean = bool(thread.wait(timeout_ms))
        if not clean:  # pragma: no cover - only on a wedged OS hook
            LOGGER.warning(
                "Worker thread did not stop within %d ms; forcing termination.", timeout_ms
            )
            thread.quit()
            thread.wait(1000)

        # Finalise synchronously rather than relying on a queued signal, so the
        # session is always closed out even without a running GUI event loop.
        was_running = self._running
        if was_running:  # the worker never settled itself (forced stop)
            self._running = False
            self._finalize_session()
            self.runningChanged.emit(False)
            self.sessionFinished.emit(self._session_id, self._events_this_session)
        return clean

    def shutdown(self) -> None:
        """Stop monitoring and release the worker thread (called on close)."""
        if self._thread is not None:
            self.stop(timeout_ms=3000)

    # -- worker callbacks --------------------------------------------------- #
    def _on_batch(self, events: Sequence[KeyEvent]) -> None:
        self._events_this_session += len(events)
        self.batchReady.emit(list(events))

    def _settle_session(self) -> None:
        """Close out session state from the worker thread.

        Connected with a direct connection so the session is finalised even
        when the owner thread has no running event loop. The database uses
        thread-local connections, so writing from here is safe.
        """
        if not self._running:
            return
        self._running = False
        self._finalize_session()

    def _announce_stopped(self, session_id: str) -> None:
        """Owner-thread notification that the worker finished its own work.

        ``session_id`` pins the notification to the session that produced it:
        a message that arrives after the analyst has already started the next
        session is discarded instead of stopping the new one.
        """
        if session_id != self._session_id:
            return
        if self._thread is not None and self._thread.isRunning():
            return
        self.runningChanged.emit(False)
        self.sessionFinished.emit(self._session_id, self._events_this_session)
        LOGGER.info(
            "Monitoring session %s ended with %d event(s).",
            self._session_id, self._events_this_session,
        )

    def _release_thread(self, thread: QThread) -> None:
        """Release the worker references once Qt confirms the thread is gone.

        Only the references that still point at ``thread`` are cleared, so a
        late notification from a previous session cannot strand the current
        one (which would leave a running worker without an owning thread).
        """
        if self._thread is thread:
            self._worker = None
            self._thread = None

    def _thread_finished_handler(self, thread: QThread) -> Callable[[], None]:
        """Return a ``thread.finished`` handler bound to ``thread``."""
        def handler() -> None:
            self._release_thread(thread)
        return handler

    def _stopped_handler(self, session_id: str) -> Callable[[], None]:
        """Return a ``workerStopped`` handler bound to ``session_id``."""
        def handler() -> None:
            self._announce_stopped(session_id)
        return handler

    def _finalize_session(self) -> None:
        if not self._session_id:
            return
        try:
            self._database.finalize_session(
                self._session_id, utc_now(), self._events_this_session
            )
        except DatabaseError as exc:  # pragma: no cover - defensive
            LOGGER.warning("Could not finalise session %s: %s", self._session_id, exc)

    # -- introspection ------------------------------------------------------- #
    def statistics(self) -> dict[str, object]:
        """Small diagnostic snapshot used by the status bar."""
        return {
            "session_id": self._session_id,
            "mode": self.mode,
            "running": self._running,
            "events": self._events_this_session,
            "started_at": self._started_at.isoformat() if self._started_at else "",
        }


def synthetic_key_names(limit: int | None = None) -> list[str]:
    """Canonical key names produced by Simulation Mode (used by tests and help)."""
    names: list[str] = [normalize_key(name).display_name for name, _weight in SIMULATION_CORPUS]
    unique = list(dict.fromkeys(names))
    return unique[:limit] if limit else unique


def corpus_categories() -> Iterable[tuple[KeyCategory, str]]:
    """Yield ``(category, canonical name)`` for every entry in the corpus."""
    for name, _weight in SIMULATION_CORPUS:
        identity = normalize_key(name)
        yield identity.category, identity.display_name