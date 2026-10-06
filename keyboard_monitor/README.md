# Keyboard Event Monitor — Authorized Security Lab

A PySide6 desktop application that records **keyboard event metadata** for
authorized security analysis in a controlled lab environment.

The monitor answers questions about *when* and *how fast* keys were pressed,
which application class had focus, and where the rate spiked — **without ever
assembling the text a person typed**. Passwords, tokens and messages cannot be
recovered from the stored data because the data never contains them.

> **Use this only on systems you own or have explicit, documented written
> permission to test.** Monitoring another person's keyboard without their
> consent is unlawful in most jurisdictions. The application enforces a consent
> gate before it will record anything, and that gate is not optional in the
> default configuration.

---

## Table of contents

- [Safety guarantees](#safety-guarantees)
- [Deliberately not implemented](#deliberately-not-implemented)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the application](#running-the-application)
- [Using the interface](#using-the-interface)
- [Architecture](#architecture)
- [Data model](#data-model)
- [Analytics](#analytics)
- [Excel export](#excel-export)
- [Configuration reference](#configuration-reference)
- [OS-specific behaviour](#os-specific-behaviour)
- [Simulation mode vs live capture](#simulation-mode-vs-live-capture)
- [Testing](#testing)
- [Limitations](#limitations)

---

## Safety guarantees

These are enforced in code and asserted by the test suite:

1. **Monitoring never starts automatically.** The analyst must tick the consent
   switch and press *Start Logging*. `EventMonitor.start()` independently
   refuses to run without `consent_acknowledged=True`, so the rule cannot be
   bypassed by calling the API directly.
2. **Redaction is on by default.** Events that occur while a window matching a
   sensitive pattern has focus are recorded as `[SENSITIVE_WINDOW_REDACTED]`.
   The matching window title is read transiently and then discarded — it never
   reaches SQLite or the spreadsheet.
3. **No typed text is ever assembled.** Only the canonical name of the key is
   stored, so sequential keystrokes cannot be replayed into a message.
4. **Passive hooks only.** Live capture registers with `suppress=False`; the
   monitor never blocks, alters or injects input.
5. **No network I/O.** Everything stays in a local SQLite database. There is no
   telemetry, no remote control channel, no update check.
6. **No persistence.** No registry key, systemd unit, launch agent, scheduled
   task or startup entry is created.
7. **No privilege escalation.** Standard, unprivileged OS APIs only. If the OS
   denies a query, the monitor degrades gracefully instead of working around it.
8. **Bounded resource use.** `max_events_per_second` and
   `max_events_per_session` hard-cap ingestion; duplicate suppression and
   rollover detection keep the database meaningful under a key held down.
9. **Sanitised input.** Every externally influenced string is stripped of
   control characters and length-bounded before it reaches SQLite or the Excel
   writer. SQL is always parameterised and sort columns come from an allow-list.
10. **Location is a label, never a coordinate.** `location_label` defaults to
    `Lab Workstation`. GPS is never requested.

## Deliberately not implemented

Kept in `security.py` as `NOT_IMPLEMENTED_BY_DESIGN` so the boundary stays
auditable:

- covert / stealth operation or window hiding
- startup persistence (registry, systemd, launch agents, scheduled tasks)
- process, DLL or code injection
- clipboard monitoring
- screenshot or screen recording
- browser credential / cookie extraction
- keystroke replay or automated input injection
- network transmission, telemetry or any remote control channel
- GPS or precise device-location collection

View the same list at runtime from the menu: **View → Show Security Policy**.

---

## Requirements

- Python 3.11 or newer (developed and verified on 3.14)
- A desktop session with a working Qt platform plugin
- No administrator/root rights are required or recommended

| Component | Version | Why |
|---|---|---|
| PySide6 | 6.11.2 | GUI toolkit |
| pandas | 3.0.2 | Builds the export data frames |
| openpyxl | 3.1.5 | Writes and styles the workbook |
| keyboard | 0.13.5 | Low-level hook (live mode only) |

Optional extras for tests and linting: `pytest`, `pytest-qt`, `pytest-mock`,
`mypy`, `ruff`, `typeguard`.

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r keyboard_monitor/requirements.txt
```

Verify the toolchain without touching the real keyboard:

```bash
python -m keyboard_monitor.main --simulation --version
```

## Running the application

```bash
python -m keyboard_monitor.main                 # honours saved settings
python -m keyboard_monitor.main --simulation    # synthetic events only
python -m keyboard_monitor.main --verbose       # DEBUG logging
python -m keyboard_monitor.main --database D:\case7\events.sqlite3
python -m keyboard_monitor.main --config C:\lab\config.json
```

| Flag | Effect |
|---|---|
| `--config PATH` | Use an explicit `config.json` instead of the per-user one. |
| `--database PATH` | Use an explicit SQLite file instead of the per-user one. |
| `--simulation` | Start in Simulation Mode; the real keyboard is never read. |
| `--verbose` | Enable DEBUG logging. |
| `--version` | Print the version and exit. |

### Per-user locations

| Purpose | Windows | macOS | Linux |
|---|---|---|---|
| Database, logs | `%LOCALAPPDATA%\KeyboardMonitorLab\` | `~/Library/Application Support/KeyboardMonitorLab/` | `$XDG_DATA_HOME/KeyboardMonitorLab/` |
| `config.json` | `%APPDATA%\KeyboardMonitorLab\` | `~/Library/Application Support/KeyboardMonitorLab/` | `$XDG_CONFIG_HOME/KeyboardMonitorLab/` |

A corrupt or unreadable `config.json` is never fatal: the built-in
privacy-by-default configuration is used instead.

## Using the interface

The window has a menu bar, a toolbar, a status strip and two tabs.

**Toolbar**

- **▶ Start Logging** — begins a session. Disabled until consent is acknowledged.
- **■ Stop Logging** — stops the session and finalises its database record.
- **⬇ Export Excel** — writes the current filtered view to a two-sheet `.xlsx`.
- **🗑 Clear Records** — deletes stored events after an explicit confirmation.
- **⚙ Settings** — location label, redaction, limits, refresh rate.
- **Consent: NOT ACKNOWLEDGED** — toggling it on asks for an explicit
  authorization confirmation.

**Tab: Keyboard Events**

The filter panel combines a key search, key category, event type, application
class, session, date range, time range, an auto-repeats-only toggle and a
**Current session only** checkbox. The result label reports
`Showing N of M events` for the active filter.

### Session scoping

**Current session only** is checked by default, and the checkbox is what scopes
the *entire* view — table, dashboard statistics, charts and Excel export all read
the same filter.

- Pressing **Start Logging** scopes the view to the session that is starting, so
  the table always opens empty and only the events of the new sequence appear.
  Nothing is deleted: earlier sessions stay in the database.
- The scope survives **Stop Logging**, so the session that just finished can be
  reviewed and exported immediately.
- Clearing the box restores access to the full history; the session dropdown
  then selects one specific session. The box is never re-ticked behind your back
  — **Clear Filters** resets the other fields but leaves the scope as you set it.
- With no session in scope (app start, or the box cleared) the filters apply
  across every stored session.

The table is a `QAbstractTableModel` view over the filtered rows — not a live
`QTableWidget` — so refreshing a 250 000-row session does not rebuild widgets.

**Tab: Dashboard**

- Twelve headline counters (totals, events/minute, unique keys, session
  duration, category subtotals, auto-repeats, redacted events, rate anomaly).
- **Key-Category Distribution** — a horizontal bar chart plus a percentage bar.
- **Application Classification** — counts per coarse application class.
- **Events Over Time (per minute)** — a vertical bar chart of the per-minute
  buckets that drives the anomaly verdict.
- **Repeated-Key / Rollover Analysis** — per-key totals and auto-repeat counts.

Both charts are hand-drawn with `QPainter` (`SimpleBarChart`), so the project
needs no plotting library. They render with an empty state, an all-zero series,
negative values and hundreds of buckets without raising.

## Architecture

```
                    ┌───────────────────────────────────────────┐
   consent gate ───▶│ MainWindow  (gui.py)                      │
   Start / Stop     │  FilterPanel · EventTableModel            │
                    │  DashboardPanel · SimpleBarChart          │
                    └───────────────┬───────────────────────────┘
                                    │ Qt signals (queued)
                    ┌───────────────▼───────────────────────────┐
                    │ EventMonitor          (event_monitor.py)   │
                    │  session lifecycle · caps · signals       │
                    └───────────────┬───────────────────────────┘
                                    │ owns
                    ┌───────────────▼───────────────────────────┐
                    │ MonitorWorker  (QThread)                  │
                    │  live hook  |  simulation corpus           │
                    │  normalize · dedupe · rollover · redact   │
                    └──────┬──────────────────────┬─────────────┘
                           │                      │
              ┌────────────▼──────┐    ┌──────────▼─────────────┐
              │ models.py         │    │ window_info.py         │
              │  normalize_key    │    │  foreground-app class  │
              │  KeyEvent         │    │  (transient, not kept) │
              └────────────┬──────┘    └────────────────────────┘
                           │
              ┌────────────▼──────────────────────────────────────┐
              │ database.py (SQLite, WAL)  ·  analytics.py       │
              │ exporter.py (pandas + openpyxl)  ·  security.py   │
              │ config.py (privacy-by-default settings)           │
              └───────────────────────────────────────────────────┘
```

| Module | Responsibility |
|---|---|
| `config.py` | `AppConfig` dataclass, `ConfigStore` (fail-safe JSON), logging, per-user paths. |
| `models.py` | Key canonicalisation, `KeyIdentity`, `KeyEvent`, modifier tracking, session ids. |
| `security.py` | Redaction policy, input sanitisation, export-path validation, guarantee lists. |
| `window_info.py` | Foreground-application classification per platform, with a short-lived cache. |
| `database.py` | Schema, indexes, filtered queries, aggregations, session bookkeeping. |
| `analytics.py` | Dashboard statistics, category percentages, rate-anomaly detection. |
| `exporter.py` | Two-sheet `.xlsx` writer with sanitised, styled output. |
| `event_monitor.py` | `MonitorWorker` (capture thread) and `EventMonitor` (GUI-facing facade). |
| `gui.py` | Main window, filter panel, table model, dashboard, charts, settings dialog. |
| `main.py` | CLI parsing, logging setup, database bootstrap, `QApplication` startup. |

### Threading model

- One `QThread` per session, at most one session at a time.
- The OS hook callback performs **no I/O**: it normalises and appends to an
  in-memory `queue.Queue`, so a keystroke burst cannot stall the OS input queue.
- The worker drains the queue on an interval, applies redaction, writes one
  transaction per batch, then emits `batchReady`.
- `workerStopped` reaches `QThread.quit` through a **direct** connection and
  settles session state on the worker thread, so a session is always finalised —
  even in a headless run with no GUI event loop.
- Both `workerStopped` and `QThread.finished` are delivered to the GUI with the
  session/thread they belong to bound into the handler. Qt posts those
  notifications, so one from a session that has already ended can arrive after
  the next session has started; without the binding it would release the *new*
  worker while its thread was still running, which Qt aborts on at shutdown.
  The guard is covered by `test_late_thread_finished_keeps_the_new_session`.
- SQLite uses thread-local connections with WAL and a 10 s busy timeout, so the
  GUI thread can read while the worker writes.

## Data model

`events`

| Column | Meaning |
|---|---|
| `id` | Autoincrement primary key. |
| `session_id` | Owning session. |
| `key_name` | Canonical key name, e.g. `A`, `Enter`, `Ctrl Left`, `F5`, `Up`. |
| `key_category` | `Letter`, `Number`, `Punctuation`, `Modifier`, `Navigation`, `Arrow`, `Function`, `Numpad`, `Other`, `Unknown`. |
| `event_type` | `key_down` or `key_up`. |
| `event_date` / `event_time` | Denormalised for fast date/time filtering. |
| `timestamp` / `epoch_ms` | Full timestamp and epoch milliseconds. |
| `application_class` | Coarse class such as `Terminal`, `Browser`, `Text Editor` — never a window title. |
| `modifier_state` | Which modifiers were held, e.g. `Ctrl+Shift`. |
| `redaction_status` | `normal` or `redacted`. |
| `location_label` | Human label from settings, e.g. `Lab Workstation`. |
| `is_repeat` | Set when the same key repeats past `repeat_threshold`. |

`sessions`

| Column | Meaning |
|---|---|
| `session_id` | Primary key. |
| `started_at` / `ended_at` | UTC boundaries. |
| `started_local` / `ended_local` | Local-time equivalents for reports. |
| `event_count` | Events recorded in the session. |
| `simulated` | Whether the session used the simulation corpus. |
| `redaction_enabled` | Whether redaction was active. |
| `location_label` | Label in force for the session. |
| `analyst_note` | Optional free-text note. |

Indexes: `timestamp`, `session_id`, `key_category`, `application_class`,
`event_type`, `(session_id, timestamp)`, `(event_date, event_time)` and
`sessions.started_at`.

## Analytics

**Rate anomaly detection** (`analytics.detect_rate_anomaly`) buckets events per
minute and compares the peak against the sample mean and standard deviation.
The verdict is `NORMAL`, `ELEVATED` or `ANOMALOUS`, and it drives both the
dashboard counter and the timeline bar colour. Small samples report `NORMAL`
rather than a spurious spike.

**Auto-repeat / rollover detection** counts consecutive `key_down` events for the
same key. Once the count passes `repeat_threshold` (default 3) the event is
flagged `is_repeat`, which separates a genuine key hold from normal typing.

**Dashboard statistics** are always computed over the *active filter*, so the
dashboard describes what the analyst is currently looking at.

## Excel export

The export writes two worksheets:

- **`Keyboard Events`** — the filtered rows, frozen header, auto-filter, sized
  columns, centred date/time columns, and a highlight fill on redacted rows.
- **`Session Summary`** — key and event counts, per-category and per-application
  breakdowns, session boundaries, and the security notice reproduced verbatim so
  a report always states its own handling conditions.

The workbook is staged in a private temporary directory and moved into place with
`os.replace`, so a failure never leaves a half-written file at the destination.
The destination must end in `.xlsx`.

## Configuration reference

`config.json` (per-user location above) accepts only known keys; unknown keys are
ignored and values are coerced to the type of their default.

| Key | Default | Effect |
|---|---|---|
| `redaction_enabled` | `true` | Redact events captured in sensitive windows. |
| `sensitive_window_patterns` | see `security.DEFAULT_SENSITIVE_PATTERNS` | Extra case-insensitive substrings treated as sensitive. |
| `location_label` | `Lab Workstation` | Stored label; no coordinates are ever collected. |
| `require_consent_acknowledgement` | `true` | Consent gate before Start. |
| `classify_foreground_application` | `true` | Ask the OS for the foreground app class. |
| `simulation_mode` | `false` | Generate synthetic events instead of reading the keyboard. |
| `simulation_events_per_second` | `12.0` | Synthetic event rate. |
| `dedupe_window_ms` | `30` | Duplicate suppression for identical `(key, event_type)` pairs. |
| `max_events_per_second` | `400` | Hard ingestion ceiling. |
| `max_events_per_session` | `250000` | Hard per-session ceiling; the worker stops when reached. |
| `repeat_threshold` | `3` | Auto-repeat count before flagging. |
| `database_filename` | `keyboard_events.sqlite3` | Database name inside the data directory. |
| `log_level` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`. |
| `gui_refresh_ms` | `250` | Table/dashboard refresh interval. |
| `table_page_size` | `500` | Rows fetched per table refresh. |
| `theme` | `dark` | Reserved for future themes. |

Prefer the **Settings** dialog over hand-editing: it validates the same fields
and saves through `ConfigStore`.

## OS-specific behaviour

| Platform | Foreground app class | Notes |
|---|---|---|
| **Windows** | `user32.GetForegroundWindow` + `QueryFullProcessImageNameW` | Fully supported. No elevation needed; a standard process can always read its own foreground window. |
| **macOS** | AppKit `NSWorkspace.frontmostApplication`, AppleScript fallback | May prompt for Accessibility permission on first use. If both paths fail the class becomes `Unknown Application`; the app keeps working. |
| **Linux / X11** | `python-xlib` `_NET_ACTIVE_WINDOW` / `_NET_WM_NAME` | Requires `python-xlib`, which is *not* installed by `requirements.txt`. Install it explicitly if you want app classification. |
| **Linux / Wayland** | Not available **by design** | Wayland deliberately blocks global key observability for unprivileged clients. The monitor reports `Unknown Application` and a notice rather than attempting a workaround. Simulation Mode is fully functional. |

Further platform caveats:

- **Live capture needs OS-granted input access.** `keyboard` uses a global hook,
  which macOS gates behind Accessibility permission and some Linux setups
  restrict. If the hook cannot be installed, the session fails with an explicit
  error and the GUI stays usable.
- **The `keyboard` library requires root on Linux** for global hooks under X11.
  This application does not request elevation. If a session cannot obtain a
  hook, use Simulation Mode, or run the analysis from a session that already has
  input access.
- **Wayland cannot be worked around.** Do not add XWayland shims or portal
  spoofing to defeat the compositor's restrictions; that is both out of scope
  and a security-boundary violation.
- On macOS, if the permission prompt is declined, remove the app from
  *System Settings → Privacy & Security → Accessibility* before retrying.

## Simulation mode vs live capture

| | Simulation | Live capture |
|---|---|---|
| Reads the real keyboard | Never | Yes, passively |
| Requires OS input permission | No | Yes |
| Event source | Weighted corpus in `event_monitor.SIMULATION_CORPUS` | `keyboard` hook (`suppress=False`) |
| Sessions flagged `simulated` | `1` | `0` |
| Works headless / over SSH / in CI | Yes | No |

Simulation Mode is the right choice for training, demos, CI and reproducing a
bug without touching anyone's input. The corpus covers every key category,
including an intentionally unmapped key so the `Unknown` path is exercised.

## Testing

```bash
pip install -r keyboard_monitor/requirements.txt

# Linux/macOS
PYTHONPATH="$PWD" QT_QPA_PLATFORM=offscreen python -m pytest -q
# Windows PowerShell
$env:PYTHONPATH="$PWD"; $env:QT_QPA_PLATFORM="offscreen"; python -m pytest -q
```

The GUI suite runs fully offscreen, so no display server is required. Modal
dialogs are replaced by non-blocking stubs, and chart tests count painted pixels
so a rendering regression fails the build rather than silently producing a blank
panel.

| Suite | Focus |
|---|---|
| `test_key_normalization.py` | Canonicalisation of every key name, categories, modifier tracking. |
| `test_database.py` | Schema, filters, aggregation, sessions, SQL-injection resistance. |
| `test_exporter.py` | Sheet names, styling, redaction, empty export, path validation. |
| `test_gui_integration.py` | Consent gate, simulation capture, table/filters/dashboard, charts, settings, export, clear-records, session scoping, clean shutdown, worker guards, stale-thread-notification race. |

Static checks:

```bash
python -m ruff check keyboard_monitor
python -m mypy keyboard_monitor --ignore-missing-imports
```

## Limitations

- Application classification is coarse by design; unknown binaries all collapse
  to `Unknown Application`.
- Wayland sessions cannot classify the foreground application.
- Key *sequences* are intentionally not reconstructed, so the data answers
  "what was pressed and how often", never "what was written".
- The GUI refreshes on an interval, so the table lags a live session by up to
  `gui_refresh_ms`.
- `max_events_per_session` stops the worker when reached; raise it only when the
  backing storage and the analysis plan justify it.
- The database is not encrypted. Protect it with OS-level access controls
  appropriate to your environment.

---

**Authorized security research and controlled lab testing only.** If you cannot
demonstrate consent for the device and the person using it, do not run this tool.
