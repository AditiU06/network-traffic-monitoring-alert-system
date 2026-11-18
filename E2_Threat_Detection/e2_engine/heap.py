"""Priority max-heap for alerts (FR-05), written by hand (binary heap in a list).

Order: higher priority first; ties -> earlier event time, then rule id, source IP,
alert id. The tie-breakers are content-based so the output order is the same on
every run (needed for sequential vs multithreaded parity).
"""
from typing import List

from .models import Alert


def _before(a: Alert, b: Alert) -> bool:
    """True if a must be popped before b."""
    if a.priority != b.priority:
        return a.priority > b.priority
    if a.event_time != b.event_time:
        return a.event_time < b.event_time
    return (a.rule_id, a.source_ip or "", a.alert_id) < (b.rule_id, b.source_ip or "", b.alert_id)


class AlertMaxHeap:
    def __init__(self):
        self._a: List[Alert] = []

    def __len__(self):
        return len(self._a)

    def peek(self) -> Alert:
        return self._a[0]

    def push(self, alert: Alert) -> None:
        a = self._a
        a.append(alert)
        i = len(a) - 1
        while i > 0:
            parent = (i - 1) // 2
            if _before(a[i], a[parent]):
                a[i], a[parent] = a[parent], a[i]
                i = parent
            else:
                break

    def pop(self) -> Alert:
        a = self._a
        top = a[0]
        last = a.pop()
        if a:
            a[0] = last
            i, n = 0, len(a)
            while True:
                l, r, best = 2 * i + 1, 2 * i + 2, i
                if l < n and _before(a[l], a[best]):
                    best = l
                if r < n and _before(a[r], a[best]):
                    best = r
                if best == i:
                    break
                a[i], a[best] = a[best], a[i]
                i = best
        return top

    def drain(self) -> List[Alert]:
        out = []
        while self._a:
            out.append(self.pop())
        return out
