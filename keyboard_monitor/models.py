"""Domain model and key-name normalization.

This module is intentionally free of Qt, SQLite and OS-specific code so it can
be unit-tested in isolation (see ``tests/test_key_normalization.py``).

Security notes
--------------
The monitor records *keyboard event metadata only* -- which key, when, in which
broad application class, and which modifiers were held.  Key *names* are single
key-cap identifiers; no text is ever assembled from a stream of keystrokes, so
there is no mechanism in this codebase for reconstructing a password, message
or any other user content.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Final, Sequence

__all__ = [
    "KeyCategory",
    "KeyGroup",
    "EventType",
    "RedactionStatus",
    "ApplicationClass",
    "KeyIdentity",
    "ModifierState",
    "ModifierTracker",
    "KeyEvent",
    "normalize_key",
    "new_session_id",
]


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class KeyCategory(str, Enum):
    """Normalized classification for a single physical key."""

    LETTER = "Letter"
    NUMBER = "Number"
    PUNCTUATION = "Punctuation"
    FUNCTION = "Function"
    MODIFIER = "Modifier"
    NAVIGATION = "Navigation"
    ARROW = "Arrow"
    NUMPAD = "Numpad"
    OTHER = "Other"
    UNKNOWN = "Unknown / Unmapped"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class KeyGroup(str, Enum):
    """Coarser grouping used by the dashboard statistics."""

    LETTERS = "Letters"
    NUMBERS = "Numbers"
    PUNCTUATION = "Punctuation"
    MODIFIERS = "Modifiers"
    NAVIGATION = "Navigation"
    ARROWS = "Arrows"
    FUNCTION = "Function Keys"
    NUMPAD = "Numpad"
    OTHER = "Other"
    UNKNOWN = "Unmapped"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


#: Mapping used to roll fine-grained categories up into dashboard groups.
_CATEGORY_TO_GROUP: Final[dict[KeyCategory, KeyGroup]] = {
    KeyCategory.LETTER: KeyGroup.LETTERS,
    KeyCategory.NUMBER: KeyGroup.NUMBERS,
    KeyCategory.PUNCTUATION: KeyGroup.PUNCTUATION,
    KeyCategory.MODIFIER: KeyGroup.MODIFIERS,
    KeyCategory.NAVIGATION: KeyGroup.NAVIGATION,
    KeyCategory.ARROW: KeyGroup.ARROWS,
    KeyCategory.FUNCTION: KeyGroup.FUNCTION,
    KeyCategory.NUMPAD: KeyGroup.NUMPAD,
    KeyCategory.OTHER: KeyGroup.OTHER,
    KeyCategory.UNKNOWN: KeyGroup.UNKNOWN,
}


class EventType(str, Enum):
    """Direction of a keyboard event."""

    KEY_DOWN = "KEY_DOWN"
    KEY_UP = "KEY_UP"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class RedactionStatus(str, Enum):
    """How much information was withheld for a recorded event."""

    NORMAL = "Normal"
    REDACTED = "Redacted"
    PARTIAL = "Partial"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class ApplicationClass(str, Enum):
    """Broad, non-identifying application classes.

    Window titles and process paths are deliberately *not* stored; only these
    coarse classes are persisted so that no user content leaks into the log.
    """

    TEXT_EDITOR = "Text Editor"
    TERMINAL = "Terminal"
    BROWSER = "Browser"
    IDE = "IDE"
    FILE_MANAGER = "File Manager"
    EMAIL = "Email Client"
    OFFICE = "Office Suite"
    SYSTEM = "System Process"
    COMMUNICATION = "Communication"
    DATABASE = "Database Tool"
    MEDIA = "Media Player"
    UNKNOWN = "Unknown Application"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


#: Every class value, handy for building filter combo boxes.
ALL_APPLICATION_CLASSES: Final[tuple[str, ...]] = tuple(c.value for c in ApplicationClass)


# --------------------------------------------------------------------------- #
# Key normalization tables
# --------------------------------------------------------------------------- #
_LETTERS: Final[str] = "abcdefghijklmnopqrstuvwxyz"
_PUNCTUATION_CANONICAL: Final[dict[str, str]] = {
    # canonical -> (shifted variant(s), aliases...)
    "-": "-_",
    "=": "+",
    "[": "{",
    "]": "}",
    "\\": "|",
    ";": ":",
    "'": '"',
    ",": "<",
    ".": ">",
    "/": "?",
    "`": "~",
}

_MODIFIER_CANONICAL: Final[tuple[str, ...]] = (
    "Esc",
    "Tab",
    "Caps Lock",
    "Shift Left",
    "Shift Right",
    "Ctrl Left",
    "Ctrl Right",
    "Alt Left",
    "Alt Right",
    "AltGr",
    "Windows Left",
    "Windows Right",
    "Menu",
)

_NAVIGATION_CANONICAL: Final[tuple[str, ...]] = (
    "Backspace",
    "Enter",
    "Space",
    "Insert",
    "Delete",
    "Home",
    "End",
    "Page Up",
    "Page Down",
)

_ARROW_CANONICAL: Final[tuple[str, ...]] = ("Up", "Down", "Left", "Right")

_NUMPAD_KEYS: Final[tuple[str, ...]] = (
    "Num Lock",
    "Numpad 0",
    "Numpad 1",
    "Numpad 2",
    "Numpad 3",
    "Numpad 4",
    "Numpad 5",
    "Numpad 6",
    "Numpad 7",
    "Numpad 8",
    "Numpad 9",
    "Numpad +",
    "Numpad -",
    "Numpad *",
    "Numpad /",
    "Numpad .",
    "Numpad Enter",
)

_OTHER_CANONICAL: Final[tuple[str, ...]] = ("Print Screen", "Scroll Lock", "Pause")


def _build_alias_table() -> dict[str, tuple[str, KeyCategory]]:
    """Build the lower-cased alias -> (canonical display, category) table."""
    table: dict[str, tuple[str, KeyCategory]] = {}

    def add(aliases: Sequence[str], canonical: str, category: KeyCategory) -> None:
        table[aliases[0].lower()] = (canonical, category)
        for alias in aliases[1:]:
            table.setdefault(alias.lower(), (canonical, category))

    # -- letters ---------------------------------------------------------- #
    for char in _LETTERS:
        add((char, f"key {char}", f"VK_{char.upper()}", f"letter {char}"),
            char.upper(), KeyCategory.LETTER)

    # -- number row ------------------------------------------------------- #
    for char in "0123456789":
        add((char, f"key {char}", f"VK_{char}", f"digit {char}", f"numeral {char}"),
            char, KeyCategory.NUMBER)
    # ``num N`` in the ``keyboard`` library denotes the *numpad* digit.
    for digit in "0123456789":
        table[f"num {digit}"] = (f"Numpad {digit}", KeyCategory.NUMPAD)
        table[f"numpad {digit}"] = (f"Numpad {digit}", KeyCategory.NUMPAD)

    # -- punctuation ------------------------------------------------------ #
    add(("-", "minus", "dash", "VK_OEM_MINUS", "key -"), "-", KeyCategory.PUNCTUATION)
    add(("_", "underscore"), "-", KeyCategory.PUNCTUATION)
    add(("=", "equals", "VK_OEM_PLUS", "key ="), "=", KeyCategory.PUNCTUATION)
    add(("+", "plus", "add (main)"), "=", KeyCategory.PUNCTUATION)
    add(("[", "left bracket", "bracketleft", "VK_OEM_4", "key ["), "[", KeyCategory.PUNCTUATION)
    add(("{", "left brace", "curlyleft"), "[", KeyCategory.PUNCTUATION)
    add(("]", "right bracket", "bracketright", "VK_OEM_6", "key ]"), "]", KeyCategory.PUNCTUATION)
    add(("}", "right brace", "curlyright"), "]", KeyCategory.PUNCTUATION)
    add(("\\", "backslash", "slash", "VK_OEM_5", "key \\"), "\\", KeyCategory.PUNCTUATION)
    add(("|", "pipe", "bar"), "\\", KeyCategory.PUNCTUATION)
    add((";", "semicolon", "VK_OEM_1", "key ;"), ";", KeyCategory.PUNCTUATION)
    add((":", "colon"), ";", KeyCategory.PUNCTUATION)
    add(("'", "apostrophe", "quote", "VK_OEM_7", "key '"), "'", KeyCategory.PUNCTUATION)
    add(('"', "double quote", "quotedbl"), "'", KeyCategory.PUNCTUATION)
    add((",", "comma", "VK_OEM_COMMA", "key ,"), ",", KeyCategory.PUNCTUATION)
    add(("<", "less than"), ",", KeyCategory.PUNCTUATION)
    add((".", "period", "dot", "VK_OEM_PERIOD", "key ."), ".", KeyCategory.PUNCTUATION)
    add((">", "greater than"), ".", KeyCategory.PUNCTUATION)
    add(("/", "slash (main)", "VK_OEM_2", "key /"), "/", KeyCategory.PUNCTUATION)
    add(("?", "question mark", "question"), "/", KeyCategory.PUNCTUATION)
    add(("`", "backquote", "grave", "VK_OEM_3", "key `"), "`", KeyCategory.PUNCTUATION)
    add(("~", "tilde", "asciitilde"), "`", KeyCategory.PUNCTUATION)

    # -- shifted number-row symbols --------------------------------------- #
    # The ``keyboard`` library reports *physical* keys, so these rarely appear;
    # they are mapped anyway so that alternative backends degrade gracefully
    # to a number-row classification instead of "Unknown / Unmapped".
    for shifted, digit in zip("!@#$%^&*()", "1234567890"):
        add((shifted, f"VK_SHIFT{digit}", f"shift {digit}", f"key {shifted}"),
            digit, KeyCategory.NUMBER)

    # -- function keys ---------------------------------------------------- #
    for index in range(1, 25):
        name = f"F{index}"
        add((name.lower(), f"key {name.lower()}", f"VK_F{index}", f"f{index}"),
            name, KeyCategory.FUNCTION)

    # -- modifiers / control keys ---------------------------------------- #
    add(("esc", "escape", "key esc"), "Esc", KeyCategory.MODIFIER)
    add(("tab", "key tab"), "Tab", KeyCategory.MODIFIER)
    add(("caps lock", "capslock", "caps_lock", "key caps lock", "VK_CAPITAL"),
        "Caps Lock", KeyCategory.MODIFIER)
    add(("shift left", "left shift", "lshift", "VK_LSHIFT", "shift"), "Shift Left", KeyCategory.MODIFIER)
    add(("shift right", "right shift", "rshift", "VK_RSHIFT"), "Shift Right", KeyCategory.MODIFIER)
    add(("ctrl left", "left ctrl", "lctrl", "control left", "VK_LCONTROL"),
        "Ctrl Left", KeyCategory.MODIFIER)
    add(("ctrl right", "right ctrl", "rctrl", "control right", "VK_RCONTROL"),
        "Ctrl Right", KeyCategory.MODIFIER)
    add(("ctrl", "control", "ctrl key"), "Ctrl Left", KeyCategory.MODIFIER)
    add(("alt left", "left alt", "lalt", "VK_LMENU", "alt option"),
        "Alt Left", KeyCategory.MODIFIER)
    add(("alt right", "right alt", "ralt", "VK_RMENU"), "Alt Right", KeyCategory.MODIFIER)
    add(("altgr", "alt gr", "alt_graph", "altgr key", "VK_CTRL_ALT"),
        "AltGr", KeyCategory.MODIFIER)
    add(("alt", "option", "alt key"), "Alt Left", KeyCategory.MODIFIER)
    add(("win left", "windows left", "left win", "lwin", "super left", "meta left",
         "cmd left", "command left", "VK_LWIN", "windows left key"),
        "Windows Left", KeyCategory.MODIFIER)
    add(("win right", "windows right", "right win", "rwin", "super right", "meta right",
         "cmd right", "command right", "VK_RWIN"),
        "Windows Right", KeyCategory.MODIFIER)
    add(("win", "windows", "super", "meta", "cmd", "command", "gui", "VK_LWIN"),
        "Windows Left", KeyCategory.MODIFIER)
    add(("menu", "context menu", "apps", "application key", "VK_APPS"),
        "Menu", KeyCategory.MODIFIER)

    # -- editing / navigation -------------------------------------------- #
    add(("backspace", "bksp", "bkspc", "back space", "VK_BACK"), "Backspace", KeyCategory.NAVIGATION)
    add(("enter", "return", "vk_return", "key enter"), "Enter", KeyCategory.NAVIGATION)
    add(("space", "spacebar", "vk_space", "key space", " "), "Space", KeyCategory.NAVIGATION)
    add(("insert", "ins", "VK_INSERT", "key insert"), "Insert", KeyCategory.NAVIGATION)
    add(("delete", "del", "VK_DELETE", "key delete"), "Delete", KeyCategory.NAVIGATION)
    add(("home", "VK_HOME", "key home"), "Home", KeyCategory.NAVIGATION)
    add(("end", "VK_END", "key end"), "End", KeyCategory.NAVIGATION)
    add(("page up", "pageup", "pgup", "prior", "VK_PRIOR"),
        "Page Up", KeyCategory.NAVIGATION)
    add(("page down", "pagedown", "pgdn", "next", "VK_NEXT"),
        "Page Down", KeyCategory.NAVIGATION)

    # -- arrows ----------------------------------------------------------- #
    add(("up", "up arrow", "arrow up", "VK_UP"), "Up", KeyCategory.ARROW)
    add(("down", "down arrow", "arrow down", "VK_DOWN"), "Down", KeyCategory.ARROW)
    add(("left", "left arrow", "arrow left", "VK_LEFT"), "Left", KeyCategory.ARROW)
    add(("right", "right arrow", "arrow right", "VK_RIGHT"), "Right", KeyCategory.ARROW)

    # -- numpad ----------------------------------------------------------- #
    add(("num lock", "numlock", "num_lock", "VK_NUMLOCK"), "Num Lock", KeyCategory.NUMPAD)
    for digit in "0123456789":
        table[f"num {digit}"] = (f"Numpad {digit}", KeyCategory.NUMPAD)
    add(("add", "numpad add", "num add", "num plus", "numpad +", "VK_ADD"),
        "Numpad +", KeyCategory.NUMPAD)
    add(("subtract", "numpad subtract", "num subtract", "numpad -", "VK_SUBTRACT"),
        "Numpad -", KeyCategory.NUMPAD)
    add(("multiply", "numpad multiply", "num multiply", "numpad *", "VK_MULTIPLY"),
        "Numpad *", KeyCategory.NUMPAD)
    add(("divide", "numpad divide", "num divide", "numpad /", "VK_DIVIDE"),
        "Numpad /", KeyCategory.NUMPAD)
    add(("decimal", "numpad decimal", "num decimal", "numpad .", "VK_DECIMAL"),
        "Numpad .", KeyCategory.NUMPAD)
    add(("enter (numpad)", "numpad enter", "num enter", "key enter (numpad)"),
        "Numpad Enter", KeyCategory.NUMPAD)

    # -- other common keys ------------------------------------------------ #
    add(("print screen", "prtsc", "prtscn", "prtscr", "printscrn", "sysrq",
         "VK_SNAPSHOT", "print screen key"), "Print Screen", KeyCategory.OTHER)
    add(("scroll lock", "scrolllock", "scroll_lock", "VK_SCROLL"),
        "Scroll Lock", KeyCategory.OTHER)
    add(("pause", "pause/break", "pause break", "break", "VK_PAUSE"), "Pause", KeyCategory.OTHER)

    return table


_ALIAS_TABLE: Final[dict[str, tuple[str, KeyCategory]]] = _build_alias_table()

#: Keys whose canonical form is itself a modifier (for the modifier tracker).
MODIFIER_DISPLAY_NAMES: Final[frozenset[str]] = frozenset(_MODIFIER_CANONICAL)

#: Canonical forms that toggle a lock rather than being held down.
LOCK_DISPLAY_NAMES: Final[frozenset[str]] = frozenset({"Caps Lock", "Num Lock"})


@dataclass(frozen=True, slots=True)
class KeyIdentity:
    """Result of normalizing a raw key name."""

    display_name: str
    category: KeyCategory

    @property
    def group(self) -> KeyGroup:
        """Dashboard grouping for this key."""
        return _CATEGORY_TO_GROUP.get(self.category, KeyGroup.UNKNOWN)

    @property
    def is_modifier(self) -> bool:
        return self.category is KeyCategory.MODIFIER

    @property
    def is_lock(self) -> bool:
        return self.display_name in LOCK_DISPLAY_NAMES


_UNKNOWN_IDENTITY: Final[KeyIdentity] = KeyIdentity(
    display_name=KeyCategory.UNKNOWN.value, category=KeyCategory.UNKNOWN
)


def _identity_for_modifier_side(name: str) -> KeyIdentity | None:
    """Handle ``shift``/``ctrl``/``alt``/``win`` names with a side suffix."""
    parts = name.split()
    if len(parts) != 2:
        return None
    base, side = parts
    if side not in {"left", "right"}:
        return None
    prefixes = {
        "shift": "Shift",
        "ctrl": "Ctrl",
        "control": "Ctrl",
        "alt": "Alt",
        "win": "Windows",
        "windows": "Windows",
        "super": "Windows",
        "meta": "Windows",
        "cmd": "Windows",
        "command": "Windows",
    }
    stem = prefixes.get(base)
    if stem is None:
        return None
    return KeyIdentity(display_name=f"{stem} {side.capitalize()}", category=KeyCategory.MODIFIER)


def normalize_key(raw_name: object) -> KeyIdentity:
    """Map a raw OS/library key name onto a canonical name and category.

    The function is total: it never raises and never returns ``None``.  Keys it
    does not recognise are reported as ``Unknown / Unmapped`` rather than
    crashing the monitor, which is what the specification requires for
    hardware-specific and unmapped scan codes.
    """
    if raw_name is None:
        return _UNKNOWN_IDENTITY
    if isinstance(raw_name, bytes):  # defensive: some backends yield bytes
        try:
            raw_name = raw_name.decode("utf-8", "ignore")
        except Exception:  # pragma: no cover - decode with 'ignore' cannot fail
            return _UNKNOWN_IDENTITY
    if not isinstance(raw_name, str):
        try:
            raw_name = str(raw_name)
        except Exception:  # pragma: no cover - pathological __str__
            return _UNKNOWN_IDENTITY

    name = raw_name.strip()
    if not name:
        return _UNKNOWN_IDENTITY

    lowered = name.lower()

    # ``keyboard`` reports unmapped scancodes like 'unidentified 00 FF 2A'.
    if lowered.startswith(("unidentified", "unknown", "vk_", "0x")):
        if lowered.startswith(("unidentified", "unknown")):
            return _UNKNOWN_IDENTITY

    direct = _ALIAS_TABLE.get(lowered)
    if direct is not None:
        return KeyIdentity(display_name=direct[0], category=direct[1])

    sided = _identity_for_modifier_side(lowered)
    if sided is not None:
        return sided

    # Windows virtual-key fallbacks such as 'VK_ADD' are handled by the table,
    # but hardware-specific keys may still slip through: report them as unmapped.
    return _UNKNOWN_IDENTITY


# --------------------------------------------------------------------------- #
# Modifier state
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ModifierState:
    """Immutable snapshot of which modifier/lock keys were held."""

    shift: bool = False
    ctrl: bool = False
    alt: bool = False
    altgr: bool = False
    win: bool = False
    caps_lock: bool = False
    num_lock: bool = False

    def as_string(self) -> str:
        """Compact human-readable form used in the table and export."""
        parts: list[str] = []
        if self.ctrl:
            parts.append("Ctrl")
        if self.alt:
            parts.append("Alt")
        if self.altgr:
            parts.append("AltGr")
        if self.shift:
            parts.append("Shift")
        if self.win:
            parts.append("Win")
        if self.caps_lock:
            parts.append("CapsLock")
        if self.num_lock:
            parts.append("NumLock")
        return "+".join(parts) if parts else "None"

    def is_empty(self) -> bool:
        return self.as_string() == "None"


class ModifierTracker:
    """Thread-safe-ish helper that maintains the current modifier state.

    Only the worker thread that consumes raw keyboard events touches this
    object, so no locking is required.
    """

    _STICKY = {
        "Caps Lock": "caps_lock",
        "Num Lock": "num_lock",
    }

    def __init__(self) -> None:
        self._held: set[str] = set()
        self._locks: set[str] = set()

    def press(self, identity: KeyIdentity) -> ModifierState:
        if identity.is_lock and identity.display_name in self._STICKY:
            if identity.display_name in self._locks:
                self._locks.discard(identity.display_name)
            else:
                self._locks.add(identity.display_name)
        elif identity.is_modifier:
            self._held.add(identity.display_name)
        return self.snapshot()

    def release(self, identity: KeyIdentity) -> ModifierState:
        if identity.is_modifier and not identity.is_lock:
            self._held.discard(identity.display_name)
        return self.snapshot()

    def reset(self) -> None:
        self._held.clear()
        self._locks.clear()

    def snapshot(self) -> ModifierState:
        def has(*names: str) -> bool:
            return any(name in self._held for name in names)

        return ModifierState(
            shift=has("Shift Left", "Shift Right"),
            ctrl=has("Ctrl Left", "Ctrl Right"),
            alt=has("Alt Left", "Alt Right"),
            altgr=has("AltGr"),
            win=has("Windows Left", "Windows Right"),
            caps_lock="Caps Lock" in self._locks,
            num_lock="Num Lock" in self._locks,
        )


# --------------------------------------------------------------------------- #
# Events and sessions
# --------------------------------------------------------------------------- #
def new_session_id() -> str:
    """Return a fresh, non-guessable session identifier."""
    return f"S-{uuid.uuid4().hex[:12].upper()}"


@dataclass(frozen=True, slots=True)
class KeyEvent:
    """A single normalized keyboard event, ready for storage.

    Note the absence of any field capable of holding typed content: the only
    string fields are a key-cap name, a coarse application class and session
    metadata.
    """

    key_name: str
    key_category: KeyCategory
    key_group: KeyGroup
    event_type: EventType
    timestamp: datetime
    session_id: str
    application_class: str = "Unknown Application"
    modifier_state: str = "None"
    redaction_status: RedactionStatus = RedactionStatus.NORMAL
    location_label: str = ""
    is_repeat: bool = False

    @property
    def event_date(self) -> str:
        """``YYYY-MM-DD`` date component (local time of the event)."""
        return self.timestamp.strftime("%Y-%m-%d")

    @property
    def event_time(self) -> str:
        """``HH:MM:SS.mmm`` time component (local time of the event)."""
        return self.timestamp.strftime("%H:%M:%S.%f")[:-3]

    @property
    def iso_timestamp(self) -> str:
        """ISO-8601 timestamp with UTC offset."""
        return self.timestamp.isoformat(timespec="milliseconds")

    def to_row(self) -> tuple[object, ...]:
        """Column tuple matching :meth:`database.Database.insert_event`."""
        return (
            self.session_id,
            self.key_name,
            self.key_category.value,
            self.event_type.value,
            self.event_date,
            self.event_time,
            self.iso_timestamp,
            self.application_class,
            self.modifier_state,
            self.redaction_status.value,
            self.location_label,
            1 if self.is_repeat else 0,
        )