"""The ONLY door between E2 and E3.

E3's code was not available when this was written, so this file defines the MINIMUM
interface E2 needs (E3Interface). Soham (E3) either implements these 3 methods, or
you write a thin adapter class around E3's existing functions. E2 never touches
the database or the log files.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class EventPage:
    events: List[Dict[str, Any]]
    next_cursor: Optional[Any] = None      # None = no more pages


@dataclass
class SaveResult:
    inserted: int
    duplicates: int = 0                    # alert_ids E3 already had (ignored, not an error)


class E3Interface(ABC):
    @abstractmethod
    def get_run_status(self, run_id: str) -> str:
        """'COMPLETED' once E1 has finished storing every event of the run."""

    @abstractmethod
    def fetch_events(self, run_id: str, cursor: Optional[Any] = None, limit: int = 5000) -> EventPage:
        """Parsed events of one run, page by page (cursor=None for the first page)."""

    @abstractmethod
    def save_alerts(self, alerts: List[Dict[str, Any]]) -> SaveResult:
        """Store alerts. Must be idempotent on alert_id (ignore, do not fail, on duplicates).
        Raise any exception on failure; E2 will retry and keep the alerts queued."""

    def mark_run_evaluated(self, run_id: str, summary: Dict[str, Any]) -> None:
        """Optional: let E3 record that E2 finished this run. Default: do nothing."""


class InMemoryE3(E3Interface):
    """Stand-in for E3 used by the tests and the demo. NOT a database."""

    def __init__(self):
        self.events: Dict[str, List[Dict[str, Any]]] = {}
        self.status: Dict[str, str] = {}
        self.alerts: Dict[str, Dict[str, Any]] = {}
        self.evaluated: Dict[str, Dict[str, Any]] = {}

    def add_events(self, run_id: str, events: Iterable[Dict[str, Any]], status: str = "COMPLETED"):
        self.events.setdefault(run_id, []).extend(events)
        self.status[run_id] = status

    def get_run_status(self, run_id):
        return self.status.get(run_id, "UNKNOWN")

    def fetch_events(self, run_id, cursor=None, limit=5000):
        data = self.events.get(run_id, [])
        start = cursor or 0
        end = start + limit
        return EventPage(data[start:end], end if end < len(data) else None)

    def save_alerts(self, alerts):
        ins = dup = 0
        for a in alerts:
            if a["alert_id"] in self.alerts:
                dup += 1
            else:
                self.alerts[a["alert_id"]] = a
                ins += 1
        return SaveResult(ins, dup)

    def mark_run_evaluated(self, run_id, summary):
        self.evaluated[run_id] = summary
