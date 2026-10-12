"""Zabbix time period strings: ``d-d,hh:mm-hh:mm;...`` (1 = Monday)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

_PART = re.compile(r"^\s*(\d)(?:\s*-\s*(\d))?\s*,\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$")


@dataclass(frozen=True)
class Interval:
    day_from: int
    day_to: int
    start: int  # minutes since midnight
    end: int


@dataclass(frozen=True)
class Period:
    intervals: tuple[Interval, ...]

    @property
    def always(self) -> bool:
        """True when the period covers the whole week."""
        for day in range(1, 8):
            covered = sorted((i.start, i.end) for i in self.intervals if i.day_from <= day <= i.day_to)
            pos = 0
            for start, end in covered:
                if start > pos:
                    return False
                pos = max(pos, end)
            if pos < 24 * 60:
                return False
        return True

    def contains(self, moment: datetime) -> bool:
        day = moment.isoweekday()
        minute = moment.hour * 60 + moment.minute
        return any(i.day_from <= day <= i.day_to and i.start <= minute < i.end for i in self.intervals)


def parse_period(text: str) -> Period | None:
    """None when the string can not be parsed (e.g. contains an unresolved macro)."""
    intervals = []
    for part in filter(None, (p.strip() for p in text.split(";"))):
        m = _PART.match(part)
        if not m:
            return None
        d1, d2 = int(m.group(1)), int(m.group(2) or m.group(1))
        start = int(m.group(3)) * 60 + int(m.group(4))
        end = int(m.group(5)) * 60 + int(m.group(6))
        if not (1 <= d1 <= d2 <= 7) or not (0 <= start < end <= 24 * 60):
            return None
        intervals.append(Interval(d1, d2, start, end))
    return Period(tuple(intervals)) if intervals else None
