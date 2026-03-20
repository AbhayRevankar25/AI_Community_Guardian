from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


MAX_HISTORY = 50
MIN_EVENTS_FOR_SCORE = 5

_WINDOW_SECS = 5 * 60  # last 5 minutes (demo-grade)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _to_epoch_seconds(dt: datetime) -> int:
    return int(dt.timestamp())


@dataclass
class _UserProfile:
    # privacy-first aggregated signals (no raw messages)
    hour_counts: list[int] = field(default_factory=lambda: [0] * 24)
    location_counts: dict[str, int] = field(default_factory=dict)

    # capped recent timestamps
    recent_alert_timestamps: list[int] = field(default_factory=list)  # all severities
    recent_high_alert_timestamps: list[int] = field(default_factory=list)  # HIGH only


PROFILES: dict[str, _UserProfile] = {}


def reset_habits() -> None:
    PROFILES.clear()


def _get_profile(user_id: str) -> _UserProfile:
    if user_id not in PROFILES:
        PROFILES[user_id] = _UserProfile()
    return PROFILES[user_id]


def update_profile(*, user_id: str, location: str, severity: str, at: datetime | None = None) -> None:
    at = at or _now_utc()
    prof = _get_profile(user_id)

    hour = at.hour
    prof.hour_counts[hour] += 1

    loc = (location or "").strip()
    if loc:
        prof.location_counts[loc] = prof.location_counts.get(loc, 0) + 1

    ts = _to_epoch_seconds(at)
    prof.recent_alert_timestamps.append(ts)
    if severity == "HIGH":
        prof.recent_high_alert_timestamps.append(ts)

    # Cap memory (bounded realism).
    if len(prof.recent_alert_timestamps) > MAX_HISTORY:
        overflow = len(prof.recent_alert_timestamps) - MAX_HISTORY
        prof.recent_alert_timestamps[:overflow] = []

    if len(prof.recent_high_alert_timestamps) > MAX_HISTORY:
        overflow = len(prof.recent_high_alert_timestamps) - MAX_HISTORY
        prof.recent_high_alert_timestamps[:overflow] = []


def _top_indices(counts: list[int], k: int) -> list[int]:
    k = max(1, int(k))
    indexed = [(i, c) for i, c in enumerate(counts)]
    indexed.sort(key=lambda x: x[1], reverse=True)
    return [i for i, c in indexed[:k] if c > 0]


def compute_unusual(*, user_id: str, location: str, at: datetime | None = None) -> dict[str, Any]:
    """
    Returns a demo-grade "unusual activity" score (0-100) and explanations.

    Minimum threshold:
      - if total_events < 5 => score=0 and explain we lack enough data
    """
    at = at or _now_utc()
    prof = _get_profile(user_id)

    total_events = len(prof.recent_alert_timestamps)
    if total_events < MIN_EVENTS_FOR_SCORE:
        return {
            "score": 0,
            "explanations": ["Not enough data for behavior analysis"],
        }

    explanations: list[str] = []
    score = 0

    loc = (location or "").strip()
    preferred_locations = sorted(prof.location_counts.items(), key=lambda kv: kv[1], reverse=True)
    preferred_location = preferred_locations[0][0] if preferred_locations else ""

    # Demo trigger #1: location differs from user's learned "normal".
    if loc and preferred_location and loc != preferred_location:
        score += 30
        explanations.append("Unusual activity detected: new location for this user")

    # Demo trigger #2: atypical hour-of-day.
    preferred_hours = _top_indices(prof.hour_counts, k=3)
    current_hour = at.hour
    if preferred_hours and current_hour not in preferred_hours:
        score += 30
        explanations.append("Unusual activity detected: atypical active hour")

    # Demo trigger #3: spike in recent HIGH alerts.
    now_ts = _to_epoch_seconds(at)
    win_start = now_ts - _WINDOW_SECS
    high_in_window = sum(1 for ts in prof.recent_high_alert_timestamps if ts >= win_start)
    if high_in_window >= 3:
        score += 40
        explanations.append("Unusual activity detected: sudden spike in alerts")

    # Normalize score (consistent 0-100).
    score = int(min(100, max(0, score)))
    return {
        "score": score,
        "explanations": explanations,
    }

