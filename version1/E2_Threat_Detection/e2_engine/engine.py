"""E2 orchestration: fetch from E3 -> normalise -> sort -> detect -> cooldown -> heap -> send to E3."""
from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional, Tuple

from .config import DEFAULT_BLACKLIST_PATH, DEFAULT_RULES_PATH, E2Config
from .cooldown import CooldownManager
from .detectors import DetectorSet
from .e3_client import E3Interface
from .heap import AlertMaxHeap
from .models import Alert, DetectionSummary, Hit, make_alert_id
from .normalizer import EventValidationError, normalize_event
from .rules_loader import load_blacklist, load_rules


def _natural(v):
    s = str(v)
    return (0, int(s), "") if s.isdigit() else (1, 0, s)


class E2Engine:
    def __init__(self, e3: Optional[E3Interface] = None, config: Optional[E2Config] = None,
                 rules_path: str = DEFAULT_RULES_PATH, blacklist_path: str = DEFAULT_BLACKLIST_PATH,
                 blacklist=None, clock=time.time, sleep=time.sleep):
        self.e3 = e3
        self.config = config or E2Config()
        self.rules = load_rules(rules_path, self.config.include_supplementary_rules)
        self.startup_warnings: List[str] = []
        if blacklist is None:
            blacklist, bad = load_blacklist(blacklist_path)
            self.startup_warnings.extend(bad)
        self.blacklist = set(blacklist)
        self.clock, self.sleep = clock, sleep
        self.pending: List[Alert] = []        # alerts E3 has not accepted yet (retry queue)

    # ------------------------------------------------------------ pure detection (no E3)
    def process_events(self, raw_events: Iterable[Any], run_id: Optional[str] = None
                       ) -> Tuple[List[Alert], DetectionSummary]:
        t0 = time.perf_counter()
        cfg = self.config
        s = DetectionSummary(run_id=run_id)
        s.rules_loaded = len(self.rules)
        self._note_errors(s, self.startup_warnings)

        events = []
        for raw in raw_events:
            s.total_events_received += 1
            try:
                events.append(normalize_event(raw, run_id))
            except EventValidationError as exc:
                self._note_errors(s, [f"invalid record skipped: {exc}"])
            except Exception as exc:                       # never let one record stop the run
                self._note_errors(s, [f"unexpected error on record: {exc!r}"])
        events.sort(key=lambda e: (e.ts, _natural(e.event_id)))   # same order in every mode

        dset = DetectorSet(self.rules, self.blacklist, cfg.max_related_events)
        s.rules_evaluated = len(dset.rules)
        cooldown = CooldownManager(cfg.cooldown_sec)
        max_cd = max([cfg.cooldown_sec] + [r.cooldown_sec or 0 for r in self.rules])
        heap = AlertMaxHeap()
        by_rule, by_sev = Counter(), Counter()

        for n, e in enumerate(events, 1):
            try:
                hits, checks = dset.evaluate(e)
                s.rule_checks += checks
                s.events_evaluated += 1
                for h in hits:
                    if cooldown.allow(h.rule.rule_id, h.src_ip, h.event_time, h.rule.cooldown_sec):
                        heap.push(self._make_alert(h, run_id))
                        s.alerts_generated += 1
                        by_rule[h.rule.rule_id] += 1
                        by_sev[h.rule.severity.name] += 1
                    else:
                        s.alerts_suppressed += 1
            except Exception as exc:
                self._note_errors(s, [f"event {e.event_id}: detection error {exc!r}"])
            if n % cfg.prune_every == 0:
                dset.prune(e.ts)
                cooldown.prune(e.ts, max_cd)

        s.alerts_by_rule, s.alerts_by_severity = dict(sorted(by_rule.items())), dict(by_sev)
        s.rules_without_eligible_data = dset.rules_without_data()
        s.duration_sec = time.perf_counter() - t0
        return heap.drain(), s

    def _make_alert(self, h: Hit, run_id) -> Alert:
        r = h.rule
        return Alert(
            alert_id=make_alert_id(run_id, r.rule_id, h.src_ip, h.trigger_event_id),
            rule_id=r.rule_id, alert_type=r.name,
            description=f"{r.name}: {r.trigger_text}. Observed: {h.detail}. Indicates: {r.indicates}.",
            severity=r.severity.name, priority=r.priority,
            detected_at=datetime.fromtimestamp(self.clock(), tz=timezone.utc).isoformat(),
            event_time=h.event_time, source_ip=h.src_ip, destination_ip=h.dst_ip,
            source_port=h.src_port, destination_port=h.dst_port,
            related_event_ids=list(h.related_event_ids), run_id=run_id)

    # ------------------------------------------------------------ full E3 round-trip
    def run(self, run_id: str) -> DetectionSummary:
        if self.e3 is None:
            raise RuntimeError("E2Engine.run() needs an E3Interface")
        cfg = self.config
        status = self.e3.get_run_status(run_id)
        if cfg.require_completed_run and status != "COMPLETED":
            raise RuntimeError(f"run {run_id} is '{status}', not COMPLETED - E1/E3 have not finished it")

        def pages():
            cursor = None
            while True:
                page = self.e3.fetch_events(run_id, cursor, cfg.page_size)
                yield from page.events
                if page.next_cursor is None:
                    return
                cursor = page.next_cursor

        alerts, s = self.process_events(pages(), run_id)
        self.pending.extend(alerts)           # heap order = Critical first
        self._flush(s)
        try:
            self.e3.mark_run_evaluated(run_id, s.to_dict())
        except Exception as exc:
            self._note_errors(s, [f"mark_run_evaluated failed: {exc!r}"])
        return s

    def flush_pending(self) -> DetectionSummary:
        s = DetectionSummary()
        self._flush(s)
        return s

    def _flush(self, s: DetectionSummary) -> None:
        size = self.config.send_batch_size
        while self.pending:
            batch = self.pending[:size]
            for attempt in range(1, self.config.max_retries + 1):
                try:
                    res = self.e3.save_alerts([a.to_dict() for a in batch])
                    s.alerts_sent += res.inserted
                    s.alerts_duplicate_at_e3 += res.duplicates
                    del self.pending[:len(batch)]
                    break
                except Exception as exc:
                    self._note_errors(s, [f"E3 save failed (attempt {attempt}): {exc!r}"])
                    if attempt < self.config.max_retries:
                        self.sleep(self.config.retry_delay_sec)
            else:
                break                          # keep the rest queued; try again on next run()
        s.alerts_pending = len(self.pending)

    def _note_errors(self, s: DetectionSummary, msgs: List[str]) -> None:
        for m in msgs:
            s.errors += 1
            if len(s.error_samples) < self.config.max_error_samples:
                s.error_samples.append(m)
