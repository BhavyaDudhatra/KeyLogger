"""Security policy, redaction and input validation.

This module is the single place where privacy decisions are made.  Everything
else in the application asks it questions instead of deciding for itself.

Guarantees enforced here
------------------------
1. **Redaction by default.**  ``RedactionPolicy`` starts with redaction enabled;
   turning it off is an explicit analyst action in Settings.
2. **No window content.**  Only a coarse :class:`~keyboard_monitor.models.
   ApplicationClass` label (or the redaction placeholder) is ever persisted.
   Window titles are used transiently for classification and then discarded.
3. **No secrets.**  There is no code path that reads passwords, tokens, card
   numbers, the clipboard or the screen.
4. **No network, no persistence, no privilege escalation.**  See
   :data:`SECURITY_GUARANTEES` and :data:`NOT_IMPLEMENTED_BY_DESIGN`.
5. **Validation.**  All externally influenced strings are length-bounded and
   control-character stripped before they reach SQLite or the Excel writer.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Iterable, Iterator, Sequence

from .models import ApplicationClass, RedactionStatus

__all__ = [
    "REDACTED_WINDOW_PLACEHOLDER",
    "DEFAULT_SENSITIVE_PATTERNS",
    "SECURITY_GUARANTEES",
    "NOT_IMPLEMENTED_BY_DESIGN",
    "RedactionPolicy",
    "sanitize_label",
    "is_valid_session_id",
    "safe_export_path",
    "secure_temp_dir",
    "utc_now",
]

REDACTED_WINDOW_PLACEHOLDER: Final[str] = "[SENSITIVE_WINDOW_REDACTED]"

#: Conservative, non-exhaustive list of window/process-name fragments that make
#: a foreground window look like it may contain sensitive material.  Matching a
#: window replaces the application classification with
#: :data:`REDACTED_WINDOW_PLACEHOLDER`; the window text itself is discarded.
DEFAULT_SENSITIVE_PATTERNS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "credential",
    "keychain",
    "keepass",
    "1password",
    "bitwarden",
    "lastpass",
    "dashlane",
    "login",
    "log in",
    "sign in",
    "signin",
    "unlock",
    "authenticate",
    "token",
    "otp",
    "mfa",
    "2fa",
    "bank",
    "payment",
    "checkout",
    "credit card",
    "cvv",
    "secret",
    "apikey",
    "api key",
    "private key",
    "seed phrase",
    "recovery phrase",
    "vault",
    "sudo",
    "administrator password",
)

_SESSION_ID_RE: Final[re.Pattern[str]] = re.compile(r"^S-[0-9A-F]{12}$")
_CONTROL_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

#: Statements shown in the About / Settings dialog and in the README.
SECURITY_GUARANTEES: Final[tuple[str, ...]] = (
    "Monitoring never starts automatically - the analyst must press Start Logging.",
    "Redaction mode is enabled by default; sensitive windows are recorded only as "
    f"{REDACTED_WINDOW_PLACEHOLDER}.",
    "No typed text is ever assembled, so passwords and other secrets cannot be recovered.",
    "No clipboard, screenshot or browser-credential access is implemented.",
    "All data stays in a local SQLite database; the application performs no network I/O.",
    "No startup entry, service, scheduled task or other persistence mechanism is created.",
    "No hidden or windowless mode, no process/DLL injection, no privilege escalation.",
    "Foreground-application lookup uses standard, unprivileged OS APIs only.",
)

#: Explicitly out of scope; kept in the source so the boundary is auditable.
NOT_IMPLEMENTED_BY_DESIGN: Final[tuple[str, ...]] = (
    "covert / stealth operation or window hiding",
    "startup persistence (registry, systemd, launch agents, scheduled tasks)",
    "process injection, DLL injection or code injection",
    "clipboard monitoring",
    "screenshot or screen recording",
    "browser credential / cookie extraction",
    "keystroke replay or automated input injection",
    "network transmission, telemetry or any remote control channel",
    "GPS or precise device-location collection",
)


def utc_now() -> datetime:
    """Timezone-aware current time (used for session boundaries)."""
    return datetime.now(timezone.utc).astimezone()


def sanitize_label(value: object, *, max_length: int = 120, default: str = "") -> str:
    """Strip control characters and bound the length of an untrusted string."""
    if value is None:
        return default
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL_CHARS_RE.sub(" ", text)
    text = " ".join(text.split())
    if max_length > 0 and len(text) > max_length:
        text = text[:max_length].rstrip()
    return text or default


def is_valid_session_id(value: object) -> bool:
    """Validate a session identifier before it is used in a query filter."""
    return isinstance(value, str) and bool(_SESSION_ID_RE.match(value))


def safe_export_path(path: object) -> Path:
    """Validate an analyst-chosen Excel export destination.

    Raises
    ------
    ValueError
        If the path is empty, not a file name, or does not end in ``.xlsx``.
    """
    if path is None:
        raise ValueError("No export destination was provided.")
    text = str(path).strip()
    if not text:
        raise ValueError("No export destination was provided.")
    if "\x00" in text:
        raise ValueError("The export path contains an invalid character.")
    candidate = Path(text).expanduser()
    if candidate.suffix.lower() != ".xlsx":
        raise ValueError("Excel exports must use the .xlsx extension.")
    if candidate.is_dir():
        raise ValueError("The export destination is a directory.")
    return candidate


@contextmanager
def secure_temp_dir(
    prefix: str = "km-export-", parent: Path | str | None = None
) -> Iterator[Path]:
    """Create a private temporary directory for staging an export.

    SECURITY: the directory is created with ``tempfile.mkdtemp`` and then
    tightened to owner-only (0700) permissions on POSIX systems, so a staged
    report is not readable by other local users while it is being written.
    ``parent`` should be the *destination* directory so that the final
    :func:`os.replace` stays on one filesystem and is therefore atomic.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=str(parent) if parent else None))
    try:
        try:
            os.chmod(path, stat.S_IRWXU)
        except (OSError, NotImplementedError):  # pragma: no cover - Windows
            pass
        yield path
    finally:
        _remove_tree(path)


def _remove_tree(path: Path) -> None:
    """Best-effort recursive delete that never raises."""
    try:
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                _remove_tree(child)
            else:
                child.unlink(missing_ok=True)
        path.rmdir()
    except OSError:  # pragma: no cover - best effort cleanup
        pass


# --------------------------------------------------------------------------- #
# Application classification keyword table
# --------------------------------------------------------------------------- #
#: Ordered ``(keyword, ApplicationClass)`` rules.  First match wins, so more
#: specific patterns are listed first.  Matching is done on the *lower-cased*
#: concatenation of process name and window title; neither string is stored.
_APPLICATION_RULES: Final[tuple[tuple[str, ApplicationClass], ...]] = (
    # IDEs before generic browser/editor matches.
    ("visual studio", ApplicationClass.IDE),
    ("devenv", ApplicationClass.IDE),
    ("pycharm", ApplicationClass.IDE),
    ("intellij", ApplicationClass.IDE),
    ("jetbrains", ApplicationClass.IDE),
    ("android studio", ApplicationClass.IDE),
    ("eclipse", ApplicationClass.IDE),
    ("netbeans", ApplicationClass.IDE),
    ("xcode", ApplicationClass.IDE),
    ("code.exe", ApplicationClass.IDE),
    ("code ", ApplicationClass.IDE),
    ("source tree", ApplicationClass.IDE),
    ("sublime", ApplicationClass.IDE),
    ("notepad++", ApplicationClass.IDE),
    ("vim", ApplicationClass.IDE),
    ("neovim", ApplicationClass.IDE),
    ("emacs", ApplicationClass.IDE),
    ("zed", ApplicationClass.IDE),
    ("cursor", ApplicationClass.IDE),
    # Terminals / shells before file managers (many are also file managers).
    ("windows terminal", ApplicationClass.TERMINAL),
    ("wt.exe", ApplicationClass.TERMINAL),
    ("cmd.exe", ApplicationClass.TERMINAL),
    ("powershell", ApplicationClass.TERMINAL),
    ("pwsh", ApplicationClass.TERMINAL),
    ("conhost", ApplicationClass.TERMINAL),
    ("alacritty", ApplicationClass.TERMINAL),
    ("kitty", ApplicationClass.TERMINAL),
    ("hyper", ApplicationClass.TERMINAL),
    ("wezterm", ApplicationClass.TERMINAL),
    ("iterm", ApplicationClass.TERMINAL),
    ("terminal.app", ApplicationClass.TERMINAL),
    ("gnome-terminal", ApplicationClass.TERMINAL),
    ("konsole", ApplicationClass.TERMINAL),
    ("xterm", ApplicationClass.TERMINAL),
    ("tilix", ApplicationClass.TERMINAL),
    ("guake", ApplicationClass.TERMINAL),
    ("terminator", ApplicationClass.TERMINAL),
    # Browsers.
    ("chrome", ApplicationClass.BROWSER),
    ("msedge", ApplicationClass.BROWSER),
    ("firefox", ApplicationClass.BROWSER),
    ("safari", ApplicationClass.BROWSER),
    ("opera", ApplicationClass.BROWSER),
    ("brave", ApplicationClass.BROWSER),
    ("vivaldi", ApplicationClass.BROWSER),
    ("librewolf", ApplicationClass.BROWSER),
    ("tor", ApplicationClass.BROWSER),
    ("chromium", ApplicationClass.BROWSER),
    ("iexplore", ApplicationClass.BROWSER),
    ("epiphany", ApplicationClass.BROWSER),
    ("thunderbird", ApplicationClass.EMAIL),
    ("outlook", ApplicationClass.EMAIL),
    ("mail.app", ApplicationClass.EMAIL),
    ("evolution", ApplicationClass.EMAIL),
    # Text editors / word processors / office.
    ("notepad", ApplicationClass.TEXT_EDITOR),
    ("wordpad", ApplicationClass.TEXT_EDITOR),
    ("textedit", ApplicationClass.TEXT_EDITOR),
    ("gedit", ApplicationClass.TEXT_EDITOR),
    ("kate", ApplicationClass.TEXT_EDITOR),
    ("leafpad", ApplicationClass.TEXT_EDITOR),
    ("nano", ApplicationClass.TEXT_EDITOR),
    ("winword", ApplicationClass.OFFICE),
    ("word.exe", ApplicationClass.OFFICE),
    ("excel", ApplicationClass.OFFICE),
    ("powerpnt", ApplicationClass.OFFICE),
    ("libreoffice", ApplicationClass.OFFICE),
    ("soffice", ApplicationClass.OFFICE),
    ("openoffice", ApplicationClass.OFFICE),
    ("onenote", ApplicationClass.OFFICE),
    # Database / developer tools.
    ("sql", ApplicationClass.DATABASE),
    ("dbeaver", ApplicationClass.DATABASE),
    ("pgadmin", ApplicationClass.DATABASE),
    ("mysql workbench", ApplicationClass.DATABASE),
    ("mongodb", ApplicationClass.DATABASE),
    ("sqlitebrowser", ApplicationClass.DATABASE),
    ("azure data studio", ApplicationClass.DATABASE),
    # File managers.
    ("explorer", ApplicationClass.FILE_MANAGER),
    ("filemanager", ApplicationClass.FILE_MANAGER),
    ("nautilus", ApplicationClass.FILE_MANAGER),
    ("files", ApplicationClass.FILE_MANAGER),
    ("dolphin", ApplicationClass.FILE_MANAGER),
    ("thunar", ApplicationClass.FILE_MANAGER),
    ("pcmanfm", ApplicationClass.FILE_MANAGER),
    ("total commander", ApplicationClass.FILE_MANAGER),
    ("ranger", ApplicationClass.FILE_MANAGER),
    ("finder", ApplicationClass.FILE_MANAGER),
    # Communication.
    ("discord", ApplicationClass.COMMUNICATION),
    ("slack", ApplicationClass.COMMUNICATION),
    ("teams", ApplicationClass.COMMUNICATION),
    ("zoom", ApplicationClass.COMMUNICATION),
    ("telegram", ApplicationClass.COMMUNICATION),
    ("signal", ApplicationClass.COMMUNICATION),
    ("element", ApplicationClass.COMMUNICATION),
    ("whatsapp", ApplicationClass.COMMUNICATION),
    # Media.
    ("vlc", ApplicationClass.MEDIA),
    ("mpv", ApplicationClass.MEDIA),
    ("spotify", ApplicationClass.MEDIA),
    ("media player", ApplicationClass.MEDIA),
    ("winamp", ApplicationClass.MEDIA),
)

#: Process names that are always classified as a system process.
_SYSTEM_PROCESSES: Final[frozenset[str]] = frozenset({
    "system", "systemd", "systemsettings", "runtime", "rundll32.exe",
    "regedit.exe", "taskmgr.exe", "control.exe", "services.exe", "lsass.exe",
    "smss.exe", "csrss.exe", "wininit.exe", "logonui.exe", "shellsurf.exe",
    "lockapp.exe", "winlogon.exe", "sihost.exe", "dwm.exe", "taskhostw.exe",
    "startmenuexperiencehost.exe", "searchhost.exe", "textinputhost.exe",
    "searchapp.exe", "applicationframehost.exe", "backgroundtaskhost.exe",
})

#: Process names that indicate a lock screen or secure desktop.
_LOCK_PROCESSES: Final[frozenset[str]] = frozenset({
    "lockapp.exe", "logonui.exe", "winlogon.exe",
    "gnome-shell", "xdg-desktop-portal", "plasmashell", "sddm-greeter",
    "lightdm", "gdm", "gdm3", "login", "cinnamon-session",
})


@dataclass(slots=True)
class RedactionPolicy:
    """Decides what an event's application classification may reveal.

    Parameters
    ----------
    enabled:
        When ``True`` (the default) events occurring in windows that look
        sensitive are recorded as :data:`REDACTED_WINDOW_PLACEHOLDER` only.
    patterns:
        Extra case-insensitive substrings that mark a window as sensitive.
    """

    enabled: bool = True
    patterns: Sequence[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_PATTERNS))

    def __post_init__(self) -> None:
        cleaned: list[str] = []
        for pattern in self.patterns:
            text = sanitize_label(pattern, max_length=80).lower()
            if text and text not in cleaned:
                cleaned.append(text)
        self.patterns = tuple(cleaned[:200])

    # -- public API ------------------------------------------------------- #
    def is_sensitive(self, process_name: object, window_title: object) -> bool:
        """Return ``True`` when the window looks like it holds secrets."""
        if not self.enabled:
            # Explicit analyst opt-out: classification still never stores text.
            return False

        proc = sanitize_label(process_name, max_length=160).lower()
        title = sanitize_label(window_title, max_length=240).lower()
        if not proc and not title:
            return False

        if proc in _LOCK_PROCESSES:
            return True

        for needle in self.patterns:
            if needle in title or needle in proc:
                return True
        return False

    def resolve(
        self, process_name: object, window_title: object
    ) -> tuple[str, RedactionStatus]:
        """Return ``(application_class, redaction_status)`` for a window.

        The window title and process name are consumed here and are *not*
        returned, propagated or stored by any caller.
        """
        if self.is_sensitive(process_name, window_title):
            return REDACTED_WINDOW_PLACEHOLDER, RedactionStatus.REDACTED
        app_class = classify_application(process_name, window_title)
        return app_class, RedactionStatus.NORMAL


def classify_application(process_name: object = "", window_title: object = "") -> str:
    """Map a window onto a coarse :class:`ApplicationClass` value.

    Returns ``"Unknown Application"`` when nothing matches or when the OS could
    not supply the information.
    """
    proc = sanitize_label(process_name, max_length=160).lower()
    title = sanitize_label(window_title, max_length=240).lower()
    if not proc and not title:
        return ApplicationClass.UNKNOWN.value
    if proc in _LOCK_PROCESSES:
        return ApplicationClass.SYSTEM.value
    if proc in _SYSTEM_PROCESSES:
        return ApplicationClass.SYSTEM.value

    haystack = f"{proc} {title}".strip()
    for keyword, app_class in _APPLICATION_RULES:
        if keyword in haystack:
            return app_class.value
    return ApplicationClass.UNKNOWN.value


def redact_text_field(value: object) -> str:
    """Placeholder used wherever sensitive *content* would otherwise be stored.

    The monitor never captures field contents, so this exists to make the
    policy explicit and reusable (and to keep the guarantee testable).
    """
    del value
    return REDACTED_WINDOW_PLACEHOLDER


def strip_sensitive_literals(candidate: str, patterns: Iterable[str] = ()) -> str:
    """Return ``candidate`` with any pattern occurrence replaced by a marker.

    Used by the exporter as a defence-in-depth pass so that even a future code
    change cannot leak a raw secret into an .xlsx file.
    """
    if not candidate:
        return ""
    text = str(candidate)
    needles = [sanitize_label(p, max_length=80) for p in patterns]
    for needle in needles:
        if not needle:
            continue
        lowered = text.lower()
        start = 0
        while True:
            index = lowered.find(needle.lower(), start)
            if index < 0:
                break
            text = text[:index] + REDACTED_WINDOW_PLACEHOLDER + text[index + len(needle):]
            lowered = text.lower()
            start = index + len(REDACTED_WINDOW_PLACEHOLDER)
    return text