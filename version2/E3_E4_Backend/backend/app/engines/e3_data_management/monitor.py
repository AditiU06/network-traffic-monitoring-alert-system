import threading


class LatencyMonitor:
    """Remembers how long each read took. Target: mean under 50 ms."""
    TARGET_MS = 50.0

    def __init__(self):
        self._lock = threading.Lock()
        self._times = {}

    def record(self, name, ms):
        with self._lock:
            self._times.setdefault(name, []).append(ms)

    def report(self):
        with self._lock:
            return {n: {"calls": len(t), "mean_ms": round(sum(t) / len(t), 2), "max_ms": round(max(t), 2),
                        "meets_target": sum(t) / len(t) < self.TARGET_MS} for n, t in self._times.items()}
