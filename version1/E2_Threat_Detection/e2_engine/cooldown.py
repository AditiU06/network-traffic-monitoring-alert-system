"""Cooldown-based duplicate suppression (FR-05). Hash map: (rule_id, ip) -> last alert time.
Uses *event* time (not wall clock) so results do not depend on how fast E2 runs."""
from typing import Dict, Tuple


class CooldownManager:
    def __init__(self, default_cooldown: float):
        self.default = default_cooldown
        self._last: Dict[Tuple[str, str], float] = {}
        self.suppressed_per_key: Dict[Tuple[str, str], int] = {}

    def allow(self, rule_id: str, ip, ts: float, cooldown=None) -> bool:
        cd = self.default if cooldown is None else cooldown
        key = (rule_id, ip or "-")
        last = self._last.get(key)
        if last is not None and ts - last < cd:
            self.suppressed_per_key[key] = self.suppressed_per_key.get(key, 0) + 1
            return False
        self._last[key] = ts
        return True

    def prune(self, now_ts: float, max_cooldown: float) -> None:
        for k in [k for k, t in self._last.items() if now_ts - t > max_cooldown]:
            del self._last[k]
