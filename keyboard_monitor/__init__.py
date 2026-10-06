"""Keyboard Event Monitor - authorized defensive security lab tool.

An offline, consent-first desktop application that records keyboard *event
metadata* (which key, when, in which coarse application class, which modifiers
held) for defensive analysis.

Safety invariants (see :mod:`keyboard_monitor.security`):
  * Monitoring never starts automatically - an analyst presses Start Logging.
  * Redaction is on by default; sensitive windows are stored only as
    ``[SENSITIVE_WINDOW_REDACTED]``.
  * No text reconstruction, no clipboard/screenshot/credential access.
  * Local SQLite storage only; no network, no persistence, no privilege
    escalation, no injection.
"""

from __future__ import annotations

from .config import (
    APP_NAME,
    APP_TITLE,
    APP_VERSION,
    AppConfig,
    ConfigStore,
    config_dir,
    data_dir,
)
from .database import Database, DatabaseError, EventFilter
from .models import (
    ApplicationClass,
    EventType,
    KeyCategory,
    KeyEvent,
    RedactionStatus,
    new_session_id,
    normalize_key,
)
from .security import REDACTED_WINDOW_PLACEHOLDER, RedactionPolicy

__version__ = APP_VERSION
__all__ = [
    "APP_NAME",
    "APP_TITLE",
    "APP_VERSION",
    "AppConfig",
    "ApplicationClass",
    "ConfigStore",
    "Database",
    "DatabaseError",
    "EventFilter",
    "EventType",
    "KeyCategory",
    "KeyEvent",
    "REDACTED_WINDOW_PLACEHOLDER",
    "RedactionPolicy",
    "RedactionStatus",
    "__version__",
    "config_dir",
    "data_dir",
    "new_session_id",
    "normalize_key",
]