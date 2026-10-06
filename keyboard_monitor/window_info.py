"""Foreground-window classification - the OS-specific part of the monitor.

Responsibilities
----------------
* Ask the operating system, using **unprivileged public APIs only**, which
  window currently has focus.
* Hand the process name and window title straight to
  :class:`~keyboard_monitor.security.RedactionPolicy`, which decides whether the
  event may be recorded normally or only as
  ``[SENSITIVE_WINDOW_REDACTED]``.
* Return a coarse :class:`~keyboard_monitor.models.ApplicationClass` string.

Nothing here reads window *contents*, raises privileges, injects code or
persists anything.  If the OS refuses the query (Wayland session, missing
Accessibility grant, sandbox, protected process) we return
``Unknown Application`` rather than trying to defeat the restriction.

Platform support matrix
-----------------------
=====================  =======================================================
Windows               ``user32.GetForegroundWindow`` + ``QueryFullProcessImageNameW``
macOS                 AppKit (``NSWorkspace.frontmostApplication``); optional
                      AppleScript fallback which needs Accessibility permission
Linux / X11            ``python-xlib`` ``_NET_ACTIVE_WINDOW`` / ``_NET_WM_NAME``
Linux / Wayland        Not available by design - returns ``Unknown Application``
=====================  =======================================================
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess  # nosec B404 - only used for the documented macOS fallback
import time
from dataclasses import dataclass
from typing import Callable, Final

from .models import ApplicationClass
from .security import RedactionPolicy, sanitize_label

LOGGER = logging.getLogger(__name__)

#: The OS refuses to identify the foreground window; we degrade gracefully.
UNKNOWN: Final[tuple[str, str]] = ("", "")

#: Cache lifetime.  Key-repeat bursts would otherwise trigger a syscall per
#: event; the active window changes far less often than once per 200 ms.
_CACHE_TTL_SECONDS: Final[float] = 0.2


@dataclass(frozen=True, slots=True)
class WindowInfo:
    """Result of a foreground-window query."""

    process_name: str
    window_title: str
    available: bool

    @property
    def unknown(self) -> bool:
        return not self.available


def _query_windows() -> WindowInfo:  # pragma: no cover - exercised on Windows only
    """Windows implementation using ``ctypes`` (no extra dependency)."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return WindowInfo("", "", False)

    title_length = user32.GetWindowTextLengthW(hwnd)
    title_buffer = ctypes.create_unicode_buffer(max(title_length + 1, 2))
    user32.GetWindowTextW(hwnd, title_buffer, len(title_buffer))
    title = title_buffer.value

    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

    process_name = ""
    # PROCESS_QUERY_LIMITED_INFORMATION is enough to read another process's
    # image path on the same user account and does NOT require elevation.
    process_query_limited = 0x1000
    handle = kernel32.OpenProcess(process_query_limited, False, pid.value)
    if handle:
        try:
            size = wintypes.DWORD(32768)
            image_buffer = ctypes.create_unicode_buffer(size.value)
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
            ]
            if kernel32.QueryFullProcessImageNameW(handle, 0, image_buffer, ctypes.byref(size)):
                process_name = os.path.basename(image_buffer.value)
        finally:
            kernel32.CloseHandle(handle)

    if not process_name:
        # Fallback: module base name via psapi (same privilege level).
        try:
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            handle = kernel32.OpenProcess(0x0400, False, pid.value)  # QUERY_INFORMATION
            if handle:
                try:
                    buffer = ctypes.create_unicode_buffer(260)
                    if psapi.GetModuleBaseNameW(handle, None, buffer, len(buffer)):
                        process_name = buffer.value
                finally:
                    kernel32.CloseHandle(handle)
        except OSError:
            pass

    available = bool(process_name or title)
    return WindowInfo(
        process_name=sanitize_label(process_name, max_length=160),
        window_title=sanitize_label(title, max_length=240),
        available=available,
    )


def _query_macos() -> WindowInfo:  # pragma: no cover - requires macOS + PyObjC
    """macOS implementation.

    Prefers AppKit via PyObjC.  If PyObjC is unavailable we try an AppleScript
    query, which needs the analyst to have granted Accessibility permission;
    if it is not granted the OS returns an error and we degrade to *Unknown*
    rather than requesting elevation.
    """
    try:
        from AppKit import NSWorkspace  # type: ignore[import-not-found]

        app = NSWorkspace.sharedWorkspace().frontmostApplication()
        name = app.localizedName() if app is not None else ""
        return WindowInfo(
            process_name=sanitize_label(name, max_length=160),
            window_title="",  # title intentionally not requested
            available=bool(name),
        )
    except Exception as exc:  # pragma: no cover - optional dependency
        LOGGER.debug("AppKit unavailable (%s); trying AppleScript fallback.", exc)

    try:
        completed = subprocess.run(  # nosec B603, B607 - fixed argv, no shell
            [
                "osascript",
                "-e",
                'tell application "System Events" to get name of first application '
                "process whose frontmost is true",
            ],
            capture_output=True,
            timeout=1.0,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        LOGGER.debug("AppleScript foreground query failed: %s", exc)
        return WindowInfo("", "", False)

    if completed.returncode != 0:
        # Typically "not allowed assistive access" - do not attempt to bypass.
        return WindowInfo("", "", False)
    name = completed.stdout.decode("utf-8", "ignore").strip()
    return WindowInfo(
        process_name=sanitize_label(name, max_length=160),
        window_title="",
        available=bool(name),
    )


def _is_wayland() -> bool:  # pragma: no cover - Linux only
    if os.environ.get("WAYLAND_DISPLAY"):
        return True
    return os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland"


def _query_linux_x11() -> WindowInfo:  # pragma: no cover - requires X11 + python-xlib
    """Linux/X11 implementation using ``python-xlib`` (optional dependency)."""
    try:
        from Xlib import X  # type: ignore[import-not-found]
        from Xlib.display import Display  # type: ignore[import-not-found]
    except Exception as exc:
        LOGGER.debug("python-xlib unavailable: %s", exc)
        return WindowInfo("", "", False)

    try:
        display = Display()
        root = display.screen().root
        window_id = root.get_full_property(
            display.intern_atom("_NET_ACTIVE_WINDOW"), X.AnyPropertyType
        )
        if not window_id or not window_id.value:
            return WindowInfo("", "", False)
        window = display.create_resource_object("window", window_id.value[0])

        title_property = window.get_full_property(
            display.intern_atom("_NET_WM_NAME"), X.AnyPropertyType
        )
        title = ""
        if title_property and title_property.value:
            title = title_property.value.decode("utf-8", "ignore")
        elif window.get_wm_name():
            title = window.get_wm_name()

        class_property = window.get_wm_class()
        process_name = ""
        if class_property:
            process_name = class_property[1] or class_property[0] or ""

        display.close()
        return WindowInfo(
            process_name=sanitize_label(process_name, max_length=160),
            window_title=sanitize_label(title, max_length=240),
            available=bool(process_name or title),
        )
    except Exception as exc:
        LOGGER.debug("X11 foreground query failed: %s", exc)
        return WindowInfo("", "", False)


def _make_backend() -> Callable[[], WindowInfo]:
    """Select the query function for the current platform."""
    system = platform.system()
    if system == "Windows":
        return _query_windows
    if system == "Darwin":
        return _query_macos
    if system == "Linux":
        if _is_wayland():
            LOGGER.info(
                "Wayland session detected: foreground-application classification is "
                "unavailable and will be reported as '%s'. This is an intentional "
                "platform limitation, not bypassed.",
                ApplicationClass.UNKNOWN.value,
            )
            return lambda: WindowInfo("", "", False)
        return _query_linux_x11
    LOGGER.info("Unsupported platform %r: foreground classification disabled.", system)
    return lambda: WindowInfo("", "", False)


class ForegroundWindowClassifier:
    """Caching front-end for the OS-specific query, with redaction applied.

    The instance is safe to call from the monitor's worker thread only; the
    GUI reads the resulting strings after they have been emitted as Qt signals.
    """

    def __init__(self, policy: RedactionPolicy, *, enabled: bool = True) -> None:
        self._policy = policy
        self._enabled = enabled
        self._backend = _make_backend()
        self._cache: tuple[float, str, str] | None = None
        self._last_error: str | None = None

    # -- introspection ----------------------------------------------------- #
    @property
    def backend_name(self) -> str:
        system = platform.system()
        if system == "Windows":
            return "Windows user32"
        if system == "Darwin":
            return "macOS AppKit"
        if system == "Linux":
            return "Linux X11 (_NET_ACTIVE_WINDOW)" if not _is_wayland() else "Unavailable (Wayland)"
        return f"Unavailable ({system})"

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def probe(self) -> WindowInfo:
        """Run the backend once, bypassing the cache (used by Settings)."""
        try:
            return self._backend()
        except Exception as exc:  # pragma: no cover - defensive
            self._last_error = str(exc)
            LOGGER.warning("Foreground window query failed: %s", exc)
            return WindowInfo("", "", False)

    # -- main API ---------------------------------------------------------- #
    def classify(self) -> tuple[str, str, str]:
        """Return ``(application_class, redaction_status, window_label)``.

        ``window_label`` is a safe diagnostic string such as ``"available"`` or
        ``"unavailable"``; it never contains window text.
        """
        if not self._enabled:
            return ApplicationClass.UNKNOWN.value, "Normal", "disabled by configuration"

        now = time.monotonic()
        if self._cache is not None and (now - self._cache[0]) < _CACHE_TTL_SECONDS:
            cached_app, cached_status = self._cache[1], self._cache[2]
            return cached_app, cached_status, "cached"

        info = self.probe()
        if info.unknown:
            app_class = ApplicationClass.UNKNOWN.value
            status = "Normal"
            label = "unavailable"
        else:
            app_class, redaction = self._policy.resolve(info.process_name, info.window_title)
            status = redaction.value
            label = "available"

        self._cache = (now, app_class, status)
        return app_class, status, label

    def invalidate(self) -> None:
        """Drop the cached lookup (called on every stop/start transition)."""
        self._cache = None