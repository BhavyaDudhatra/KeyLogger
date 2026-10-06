"""Defensive-analysis statistics for recorded keyboard events.

Everything here is derived from stored *metadata* (key names, categories,
timings, coarse application classes).  No new observation of the analyst's
activity is performed, so running analytics never expands the privacy surface.

The dashboard consumes :class:`DashboardStats`; the charts in the GUI consume
:attr:`DashboardStats.category_series` and :attr:`DashboardStats.timeline_series`.
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Sequence

from .database import Database, EventFilter, SessionRecord
from .models import KeyCategory

LOGGER = logging.getLogger(__name__)

__all__ = [
    "DashboardStats",
    "AnomalyReport",
    "compute_dashboard",
    "build_session_stats",
    "CATEGORY_DISPLAY_ORDER",
]

#: Order in which the key-category breakdown is presented on the dashboard.
CATEGORY_DISPLAY_ORDER: Final[tuple[str, ...]] = (
    KeyCategory.LETTER.value,
    KeyCategory.NUMBER.value,
    KeyCategory.PUNCTUATION.value,
    KeyCategory.MODIFIER.value,
    KeyCategory.NAVIGATION.value,
    KeyCategory.ARROW.value,
    KeyCategory.FUNCTION.value,
    KeyCategory.NUMPAD.value,
    KeyCategory.OTHER.value,
    KeyCategory.UNKNOWN.value,
)

#: Only buckets this many standard deviations above the local mean are flagged.
ANOMALY_SIGMA: Final[float] = 3.0
#: A per-minute rate above this many events is considered "very fast typing".
HIGH_RATE_EVENTS_PER_MINUTE: Final[float] = 300.0


@dataclass(slots=True)
class AnomalyReport:
    """Event-rate anomaly assessment for a session or filtered view."""

    level: str = "normal"  # normal | elevated | anomalous
    message: str = "No anomalies detected."
    mean_per_minute: float = 0.0
    peak_per_minute: int = 0
    peak_bucket: str = ""
    sigma: float = 0.0
    sample_size: int = 0

    @property
    def is_anomalous(self) -> bool:
        return self.level == "anomalous"

    @property
    def display_level(self) -> str:
        return {
            "normal": "NORMAL",
            "elevated": "ELEVATED",
            "anomalous": "ANOMALOUS",
        }.get(self.level, "NORMAL")


@dataclass(slots=True)
class DashboardStats:
    """Everything the dashboard and the export summary need."""

    total_events: int = 0
    key_down: int = 0
    key_up: int = 0
    unique_keys: int = 0
    repeat_events: int = 0
    redacted_events: int = 0
    events_per_minute: float = 0.0
    session_duration_seconds: float = 0.0
    started_at: datetime | None = None
    ended_at: datetime | None = None
    session_id: str = ""
    category_series: list[tuple[str, int]] = field(default_factory=list)
    application_series: list[tuple[str, int]] = field(default_factory=list)
    timeline_series: list[tuple[str, int]] = field(default_factory=list)
    modifier_series: list[tuple[str, int]] = field(default_factory=list)
    navigation_series: list[tuple[str, int]] = field(default_factory=list)
    function_series: list[tuple[str, int]] = field(default_factory=list)
    repeat_series: list[tuple[str, int, int]] = field(default_factory=list)
    category_percentages: list[tuple[str, float]] = field(default_factory=list)
    anomaly: AnomalyReport = field(default_factory=AnomalyReport)

    def percentage(self, category: str) -> float:
        """Percentage of events belonging to ``category``."""
        for name, value in self.category_percentages:
            if name == category:
                return value
        return 0.0

    @property
    def duration_text(self) -> str:
        total = int(max(0.0, self.session_duration_seconds))
        hours, remainder = divmod(total, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def repeat_ratio(self) -> float:
        """Share of events that were auto-repeats of a held key."""
        if not self.total_events:
            return 0.0
        return (self.repeat_events / self.total_events) * 100.0


def _parse(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def detect_rate_anomaly(timeline: Sequence[tuple[str, int]]) -> AnomalyReport:
    """Flag unusually fast key-event bursts.

    Uses a median/MAD style robust estimate so a single spike does not inflate
    the baseline and hide itself.
    """
    counts = [int(count) for _bucket, count in timeline if int(count) > 0]
    if len(counts) < 3:
        return AnomalyReport(
            level="normal",
            message="Not enough data yet to assess event rate.",
            peak_per_minute=max(counts) if counts else 0,
            sample_size=len(counts),
        )

    mean = statistics.fmean(counts)
    try:
        sigma = statistics.stdev(counts) if len(counts) > 1 else 0.0
    except statistics.StatisticsError:  # pragma: no cover - guarded by len check
        sigma = 0.0

    peak_value = max(counts)
    peak_bucket = next(bucket for bucket, count in timeline if int(count) == peak_value)
    report = AnomalyReport(
        level="normal",
        mean_per_minute=mean,
        peak_per_minute=peak_value,
        peak_bucket=peak_bucket,
        sigma=sigma,
        sample_size=len(counts),
    )

    if sigma <= 0.0:
        if peak_value > HIGH_RATE_EVENTS_PER_MINUTE:
            report.level = "anomalous"
            report.message = (
                f"Sustained rate of {peak_value} events/min at {peak_bucket} exceeds the "
                f"{HIGH_RATE_EVENTS_PER_MINUTE:.0f} events/min review threshold."
            )
        else:
            report.message = (
                f"Steady event rate (average {mean:.1f} events/min); no rate anomalies."
            )
        return report

    if peak_value > mean + ANOMALY_SIGMA * sigma:
        report.level = "anomalous"
        report.message = (
            f"Event rate spike at {peak_bucket}: {peak_value} events/min is "
            f"{(peak_value - mean) / sigma:.1f} sigma above the average of {mean:.1f}/min."
        )
    elif peak_value > mean + 2.0 * sigma or peak_value > HIGH_RATE_EVENTS_PER_MINUTE:
        report.level = "elevated"
        report.message = (
            f"Elevated event rate: peak {peak_value} events/min at {peak_bucket} "
            f"(average {mean:.1f}/min)."
        )
    else:
        report.message = (
            f"Event rate within expected range (average {mean:.1f} events/min, "
            f"peak {peak_value}/min)."
        )
    return report


def build_session_stats(
    database: Database,
    criteria: EventFilter,
    session: SessionRecord | None,
) -> DashboardStats:
    """Assemble dashboard statistics for a filtered event set."""
    stats = DashboardStats()
    summary = database.summarize(criteria)

    stats.total_events = summary.total_events
    stats.key_down = summary.key_down
    stats.key_up = summary.key_up
    stats.unique_keys = summary.unique_keys
    stats.repeat_events = summary.repeat_events
    stats.redacted_events = summary.redacted_events
    stats.session_id = criteria.session_id or (session.session_id if session else "")

    # -- session window ---------------------------------------------------- #
    if session is not None:
        stats.started_at = _parse(session.started_at)
        stats.ended_at = _parse(session.ended_at) if session.ended_at else None
    stats.started_at = stats.started_at or _parse(summary.first_timestamp)
    stats.ended_at = stats.ended_at or _parse(summary.last_timestamp)

    if stats.started_at and stats.ended_at and stats.ended_at >= stats.started_at:
        stats.session_duration_seconds = (stats.ended_at - stats.started_at).total_seconds()
    if stats.session_duration_seconds <= 0 and stats.total_events:
        # A live session has no end timestamp yet; fall back to the elapsed time
        # since the first event so "events/minute" is still meaningful.
        stats.session_duration_seconds = max(1.0, _elapsed_since(stats.started_at))
    if stats.session_duration_seconds > 0:
        stats.events_per_minute = stats.total_events / (stats.session_duration_seconds / 60.0)

    # -- breakdowns --------------------------------------------------------- #
    stats.category_series = _ordered_categories(summary.categories)
    stats.category_percentages = _percentages(stats.category_series, stats.total_events)
    stats.application_series = summary.applications[:12]

    by_category = _ordered_categories(summary.categories)
    stats.modifier_series = [
        (name, count) for name, count in by_category
        if name == KeyCategory.MODIFIER.value
    ]
    stats.navigation_series = [
        (name, count) for name, count in by_category
        if name in {KeyCategory.NAVIGATION.value, KeyCategory.ARROW.value}
    ]
    stats.function_series = [
        (name, count) for name, count in by_category
        if name == KeyCategory.FUNCTION.value
    ]

    # -- timeline / repeats -------------------------------------------------- #
    stats.timeline_series = database.events_per_minute(criteria)
    stats.anomaly = detect_rate_anomaly(stats.timeline_series)

    try:
        stats.repeat_series = database.top_repeated_keys(limit=10)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("Repeat statistics unavailable: %s", exc)

    return stats


def _elapsed_since(moment: datetime | None) -> float:
    if moment is None:
        return 1.0
    from .security import utc_now

    now = utc_now()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=now.tzinfo)
    return max(1.0, (now - moment).total_seconds())


def _ordered_categories(pairs: Sequence[tuple[str, int]]) -> list[tuple[str, int]]:
    """Order ``(name, count)`` pairs by :data:`CATEGORY_DISPLAY_ORDER`."""
    lookup = {str(name): int(count) for name, count in pairs}
    ordered = [(name, lookup[name]) for name in CATEGORY_DISPLAY_ORDER if name in lookup]
    extra = sorted(
        ((name, count) for name, count in lookup.items() if name not in CATEGORY_DISPLAY_ORDER),
        key=lambda item: item[1], reverse=True,
    )
    return ordered + extra


def _percentages(
    pairs: Sequence[tuple[str, int]], total: int
) -> list[tuple[str, float]]:
    if total <= 0:
        return [(name, 0.0) for name, _count in pairs]
    return [(name, (count / total) * 100.0) for name, count in pairs]


def compute_dashboard(
    database: Database,
    criteria: EventFilter | None = None,
    session: SessionRecord | None = None,
) -> DashboardStats:
    """Public entry point used by the GUI refresh timer."""
    criteria = (criteria or EventFilter()).sanitized()
    try:
        return build_session_stats(database, criteria, session)
    except Exception as exc:  # pragma: no cover - the GUI must never die on stats
        LOGGER.warning("Dashboard statistics could not be computed: %s", exc)
        return DashboardStats(anomaly=AnomalyReport(
            level="normal",
            message=f"Statistics unavailable: {exc}",
        ))