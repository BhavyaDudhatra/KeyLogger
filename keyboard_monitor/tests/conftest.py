"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterator

import pytest

# Make the package importable when pytest is invoked from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from keyboard_monitor.config import AppConfig  # noqa: E402
from keyboard_monitor.database import Database  # noqa: E402
from keyboard_monitor.models import (  # noqa: E402
    EventType,
    KeyCategory,
    KeyEvent,
    KeyGroup,
    RedactionStatus,
    new_session_id,
)
from keyboard_monitor.security import utc_now  # noqa: E402


@pytest.fixture()
def config(tmp_path: Path) -> AppConfig:
    """An isolated, simulation-mode configuration backed by ``tmp_path``."""
    return AppConfig(
        simulation_mode=True,
        database_filename=str(tmp_path / "events.sqlite3").replace("\\", "_"),
    ).sanitized()


@pytest.fixture()
def database(tmp_path: Path) -> Iterator[Database]:
    """A fresh, initialized SQLite database inside ``tmp_path``."""
    db = Database(tmp_path / "events.sqlite3")
    db.initialize()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def session_id() -> str:
    return new_session_id()


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
    """Build a :class:`KeyEvent` for tests with sensible defaults."""
    from datetime import timedelta

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
def event_factory():
    """Expose :func:`make_event` as a fixture."""
    return make_event


@pytest.fixture()
def seeded_events(session_id: str):
    """A small, deterministic batch spanning several categories."""

    def build() -> list[KeyEvent]:
        rows = [
            make_event(session_id=session_id, key_name="A"),
            make_event(session_id=session_id, key_name="Shift",
                       category=KeyCategory.MODIFIER, group=KeyGroup.MODIFIERS),
            make_event(session_id=session_id, key_name="F5",
                       category=KeyCategory.FUNCTION, group=KeyGroup.FUNCTION),
            make_event(session_id=session_id, key_name="Up",
                       category=KeyCategory.ARROW, group=KeyGroup.ARROWS),
            make_event(session_id=session_id, key_name="Enter",
                       category=KeyCategory.NAVIGATION, group=KeyGroup.NAVIGATION,
                       event_type=EventType.KEY_UP),
        ]
        return rows

    return build