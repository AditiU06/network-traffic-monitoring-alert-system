"""Adapter connecting E2Engine to Engine 3's DataManagementService.

Translates E2's E3Interface methods into calls on E3's DataManagementService:
- get_run_status(run_id) -> e3.get_run(run_id)["status"]
- fetch_events(run_id, cursor, limit) -> e3.get_events_for_detection(run_id, limit, cursor)
- save_alerts(alerts) -> transforms to E3's schema and calls e3.save_alerts()
- mark_run_evaluated(run_id, summary) -> e3.mark_events_evaluated()
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Ensure E3 backend package root is on sys.path
_backend_root = Path(__file__).resolve().parent.parent.parent / "E3_E4_Backend" / "backend"
if _backend_root.exists() and str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from e2_engine.e3_client import E3Interface, EventPage, SaveResult


class E3ServiceAdapter(E3Interface):
    """Bridges E2 to Team 14's DataManagementService."""

    def __init__(self, service_or_db_path: Any):
        """
        service_or_db_path can be an instance of DataManagementService,
        or a path (str) to SQLite database file.
        """
        if isinstance(service_or_db_path, str):
            from app.engines.e3_data_management.service import DataManagementService
            self.service = DataManagementService(service_or_db_path)
        else:
            self.service = service_or_db_path

        self._evaluated_event_ids: List[str] = []
        self._seen_event_ids: Set[str] = set()

    def get_run_status(self, run_id: str) -> str:
        try:
            run = self.service.get_run(run_id)
            return run.get("status", "UNKNOWN")
        except Exception:
            return "UNKNOWN"

    def fetch_events(self, run_id: str, cursor: Optional[Any] = None, limit: int = 5000) -> EventPage:
        # E3's get_events_for_detection returns unevaluated events ordered by timestamp, event_id
        events = self.service.get_events_for_detection(run_id, limit=limit, cursor=cursor)
        for ev in events:
            eid = str(ev.get("event_id"))
            if eid and eid not in self._seen_event_ids:
                self._seen_event_ids.add(eid)
                self._evaluated_event_ids.append(eid)

        # If fetched fewer than limit, there are no more pages
        if len(events) < limit:
            next_cursor = None
        else:
            last_ev = events[-1]
            next_cursor = (last_ev["event_timestamp"], str(last_ev["event_id"]))

        return EventPage(events=events, next_cursor=next_cursor)

    def save_alerts(self, alerts: List[Dict[str, Any]]) -> SaveResult:
        if not alerts:
            return SaveResult(inserted=0, duplicates=0)

        formatted_alerts = []
        for a in alerts:
            # Map E2 alert dictionary to E3 database table columns
            rule_code = a.get("rule_id") or a.get("rule_code") or a.get("alert_type") or "UNKNOWN_RULE"
            affected_ip = a.get("source_ip") or a.get("destination_ip") or a.get("affected_ip") or "0.0.0.0"
            detected_at = a.get("detected_at")
            window_start = a.get("window_start") or detected_at

            formatted_alerts.append({
                "alert_id": a["alert_id"],
                "run_id": a["run_id"],
                "severity": str(a.get("severity", "LOW")).upper(),
                "rule_code": rule_code,
                "affected_ip": affected_ip,
                "window_start": window_start,
                "detected_at": detected_at,
                "description": a.get("description", ""),
                "related_event_ids": [str(x) for x in a.get("related_event_ids", [])],
                "suppression_count": a.get("suppression_count", 0),
            })

        res = self.service.save_alerts(formatted_alerts)
        inserted = res.get("inserted", 0)
        duplicates = res.get("suppressed", 0)
        return SaveResult(inserted=inserted, duplicates=duplicates)

    def mark_run_evaluated(self, run_id: str, summary: Dict[str, Any]) -> None:
        if self._evaluated_event_ids:
            self.service.mark_events_evaluated(self._evaluated_event_ids)
            self._evaluated_event_ids.clear()
            self._seen_event_ids.clear()
