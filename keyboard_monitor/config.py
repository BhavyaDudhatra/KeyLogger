"""Configuration handling for the Keyboard Event Monitor.

Security notes
--------------
* Privacy-by-default: redaction is ON out of the box and the analyst must
  explicitly opt out in Settings.  Monitoring never starts automatically.
* No setting in this file enables network access, persistence or privilege
  escalation.  Those capabilities are intentionally not implemented at all.
* The configuration file is plain JSON stored in the per-user configuration
  directory.  It holds *no* secrets: only analyst preferences.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import platform
import tempfile
from dataclasses import MISSING, asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .security import DEFAULT_SENSITIVE_PATTERNS

__all__ = [
    "APP_NAME",
    "APP_TITLE",
    "APP_VERSION",
    "REDACTED_WINDOW_PLACEHOLDER",
    "UNKNOWN_APPLICATION",
    "UNKNOWN_WINDOW",
    "DEFAULT_LOCATION_LABEL",
    "DEFAULT_SENSITIVE_PATTERNS",
    "AppConfig",
    "ConfigStore",
    "config_dir",
    "data_dir",
    "ensure_dir",
    "configure_logging",
]

LOGGER = logging.getLogger(__name__)

APP_NAME = "KeyboardMonitorLab"
APP_TITLE = "Keyboard Event Monitor - Authorized Security Lab"
APP_VERSION = "1.0.0"

#: Text that is substituted for the application/window classification when the
#: foreground window looks like it may contain sensitive material.  No window
#: *content* is ever captured, only this marker.
REDACTED_WINDOW_PLACEHOLDER = "[SENSITIVE_WINDOW_REDACTED]"

#: Value used when the operating system cannot tell us the foreground window.
UNKNOWN_APPLICATION = "Unknown Application"
UNKNOWN_WINDOW = "Unknown"

#: The monitor never records GPS or any other precise physical location.
#: A human-readable device label is used instead (see :attr:`AppConfig.location_label`).
DEFAULT_LOCATION_LABEL = "Lab Workstation"


def config_dir() -> Path:
    """Return the per-user configuration directory for the application."""
    system = platform.system()
    if system == "Windows":
        root = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        base = Path(root)
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        root = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        base = Path(root)
    return base / APP_NAME


def data_dir() -> Path:
    """Return the per-user data directory (SQLite database, exports, logs)."""
    system = platform.system()
    if system == "Windows":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        base = Path(root)
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        root = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        base = Path(root)
    return base / APP_NAME


def ensure_dir(path: Path) -> Path:
    """Create ``path`` (and parents) with owner-only permissions where possible."""
    path.mkdir(parents=True, exist_ok=True)
    # SECURITY: analyst data (event metadata) stays owner-only on POSIX systems.
    try:
        os.chmod(path, 0o700)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows
        pass
    return path


@dataclass(slots=True)
class AppConfig:
    """Analyst preferences.  Every privacy-relevant default is restrictive."""

    # --- privacy / safety -------------------------------------------------
    #: Redact events that occur inside windows judged to be sensitive.
    redaction_enabled: bool = True
    #: Extra case-insensitive substrings treated as sensitive window markers.
    sensitive_window_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_SENSITIVE_PATTERNS)
    )
    #: Never resolve or store physical location; use a human-readable label.
    location_label: str = DEFAULT_LOCATION_LABEL
    #: Operator must acknowledge the consent notice before Start is enabled.
    require_consent_acknowledgement: bool = True

    # --- collection -------------------------------------------------------
    #: Ask the OS for the foreground application class (no window titles kept).
    classify_foreground_application: bool = True
    #: Generate synthetic events instead of reading the real keyboard.
    simulation_mode: bool = False
    #: Synthetic events per second while in simulation mode.
    simulation_events_per_second: float = 12.0
    #: Duplicate suppression window for identical (key, event_type) pairs.
    dedupe_window_ms: int = 30
    #: Hard ceiling on events ingested per second (protects the GUI/DB).
    max_events_per_second: int = 400
    #: Hard ceiling on events retained for a single session.
    max_events_per_session: int = 250_000
    #: Auto-repeat (key rollover) detection window for the same held key.
    repeat_threshold: int = 3

    # --- storage / UI -----------------------------------------------------
    database_filename: str = "keyboard_events.sqlite3"
    log_level: str = "INFO"
    gui_refresh_ms: int = 250
    table_page_size: int = 500
    theme: str = "dark"

    # ------------------------------------------------------------------ #
    @property
    def database_path(self) -> Path:
        """Absolute path of the SQLite database file."""
        return data_dir() / self.database_filename

    def validate(self) -> list[str]:
        """Return a list of human-readable validation problems.

        Input validation is a security control: malformed configuration must
        never be able to point the monitor at an arbitrary file or produce
        pathological resource use.
        """
        problems: list[str] = []

        if not self.database_filename or Path(self.database_filename).name != self.database_filename:
            problems.append("database_filename must be a plain file name (no path separators).")

        if not (0 <= self.dedupe_window_ms <= 1000):
            problems.append("dedupe_window_ms must be between 0 and 1000.")

        if not (1 <= self.max_events_per_second <= 100_000):
            problems.append("max_events_per_second must be between 1 and 100000.")

        if not (1 <= self.max_events_per_session <= 10_000_000):
            problems.append("max_events_per_session must be between 1 and 10000000.")

        if not (1 <= self.repeat_threshold <= 1000):
            problems.append("repeat_threshold must be between 1 and 1000.")

        if not (0.5 <= self.simulation_events_per_second <= 1000.0):
            problems.append("simulation_events_per_second must be between 0.5 and 1000.")

        if not (50 <= self.gui_refresh_ms <= 5000):
            problems.append("gui_refresh_ms must be between 50 and 5000 ms.")

        if self.theme not in {"dark", "light"}:
            problems.append("theme must be 'dark' or 'light'.")

        if not self.location_label.strip():
            problems.append("location_label must not be empty.")
        if len(self.location_label) > 120:
            problems.append("location_label must be 120 characters or fewer.")

        if len(self.sensitive_window_patterns) > 200:
            problems.append("At most 200 sensitive window patterns are allowed.")
        for pattern in self.sensitive_window_patterns:
            if len(pattern) > 80:
                problems.append("Sensitive window patterns must be 80 characters or fewer.")
                break

        return problems

    def sanitized(self) -> "AppConfig":
        """Return a copy with values clamped into safe ranges."""
        data = asdict(self)
        data["dedupe_window_ms"] = min(max(int(data["dedupe_window_ms"]), 0), 1000)
        data["max_events_per_second"] = min(max(int(data["max_events_per_second"]), 1), 100_000)
        data["max_events_per_session"] = min(max(int(data["max_events_per_session"]), 1), 10_000_000)
        data["repeat_threshold"] = min(max(int(data["repeat_threshold"]), 1), 1000)
        data["gui_refresh_ms"] = min(max(int(data["gui_refresh_ms"]), 50), 5000)
        data["simulation_events_per_second"] = min(max(float(data["simulation_events_per_second"]), 0.5), 1000.0)
        data["theme"] = data["theme"] if data["theme"] in {"dark", "light"} else "dark"
        data["location_label"] = (data["location_label"] or DEFAULT_LOCATION_LABEL)[:120]
        name = str(data["database_filename"])
        data["database_filename"] = Path(name).name if Path(name).name == name else "keyboard_events.sqlite3"
        data["sensitive_window_patterns"] = [
            str(p)[:80] for p in data["sensitive_window_patterns"] if str(p).strip()
        ][:200]
        valid = {f.name for f in fields(self)}
        return AppConfig(**{k: v for k, v in data.items() if k in valid})


class ConfigStore:
    """Loads/saves :class:`AppConfig` as JSON with fail-safe behaviour.

    A corrupted or unreadable configuration file never prevents start-up: the
    built-in privacy-by-default configuration is used instead.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else config_dir() / "config.json"

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> AppConfig:
        if not self._path.exists():
            return AppConfig()
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            LOGGER.warning("Could not read config %s (%s); using defaults.", self._path, exc)
            return AppConfig()
        if not isinstance(raw, dict):
            LOGGER.warning("Config %s is not a JSON object; using defaults.", self._path)
            return AppConfig()

        known = {f.name: f for f in fields(AppConfig)}
        kwargs: dict[str, Any] = {}
        for key, value in raw.items():
            spec = known.get(key)
            if spec is None:
                continue  # ignore unknown keys
            try:
                # ``spec.type`` is a string under PEP 563, so infer the target
                # type from the field default instead of the annotation.
                if spec.default is not MISSING:
                    expected: type = type(spec.default)
                elif spec.default_factory is not MISSING:  # type: ignore[misc]
                    expected = type(spec.default_factory())  # type: ignore[misc]
                else:  # pragma: no cover - every field has a default here
                    expected = str

                if expected is list:
                    if isinstance(value, list):
                        kwargs[key] = [str(item)[:80] for item in value if isinstance(item, (str, int))][:200]
                elif expected is bool:
                    kwargs[key] = bool(value)
                elif expected is int:
                    kwargs[key] = int(value)
                elif expected is float:
                    kwargs[key] = float(value)
                elif expected is str:
                    kwargs[key] = str(value)[:200]
            except (TypeError, ValueError):
                LOGGER.warning("Ignoring malformed config value for %r", key)
        return AppConfig(**kwargs).sanitized()

    def save(self, config: AppConfig) -> None:
        """Persist ``config``; write via a secure temp file then replace."""
        try:
            ensure_dir(self._path.parent)
            payload = json.dumps(asdict(config), indent=2, sort_keys=True)
            # SECURITY: mkstemp creates the file with 0600 permissions on POSIX.
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self._path.parent), prefix="config-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_name, self._path)
            except BaseException:
                _silent_unlink(Path(tmp_name))
                raise
        except OSError as exc:
            LOGGER.warning("Could not save config %s: %s", self._path, exc)


def _silent_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - best effort cleanup
        pass


def configure_logging(level: str = "INFO", *, log_file: Path | None = None) -> None:
    """Configure application-wide logging.

    Logs are diagnostics only: they never contain captured event payloads, and
    the log file lives in the per-user data directory.
    """
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    stream.setLevel(numeric)
    root.addHandler(stream)

    try:
        target_dir = ensure_dir(data_dir() / "logs")
        file_handler = logging.handlers.RotatingFileHandler(
            target_dir / "keyboard_monitor.log",
            maxBytes=2_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(numeric)
        root.addHandler(file_handler)
        if log_file is not None:  # pragma: no cover - optional override
            del log_file
    except OSError as exc:  # pragma: no cover - read-only home directories
        root.warning("File logging disabled: %s", exc)