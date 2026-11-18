"""Data models and validation structures for Engine 1 (E1) Concurrent Log Processing."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ParseErrorRecord:
    """Represents a single parsing or validation error in a Zeek log."""
    line_number: int
    raw_line: str
    error_category: str
    error_message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_number": self.line_number,
            "raw_line": self.raw_line[:500],  # Avoid unbounded raw line payloads
            "error_category": self.error_category,
            "error_message": self.error_message,
        }


@dataclass
class BenchmarkResult:
    """Genuine execution and resource measurement metrics for E1."""
    record_count: int
    worker_count: int
    sequential_time_sec: float
    parallel_time_sec: float
    sequential_throughput_eps: float
    parallel_throughput_eps: float
    actual_speedup: float
    sequential_cpu_pct: Optional[float] = None
    parallel_cpu_pct: Optional[float] = None
    sequential_memory_mb: Optional[float] = None
    parallel_memory_mb: Optional[float] = None
    equivalence_status: str = "PASS"
    mismatch_count: int = 0
    mismatch_details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_count": self.record_count,
            "worker_count": self.worker_count,
            "sequential_time_sec": round(self.sequential_time_sec, 6),
            "parallel_time_sec": round(self.parallel_time_sec, 6),
            "sequential_throughput_eps": round(self.sequential_throughput_eps, 2),
            "parallel_throughput_eps": round(self.parallel_throughput_eps, 2),
            "speedup_ratio": round(self.actual_speedup, 2),
            "sequential_cpu_pct": self.sequential_cpu_pct,
            "parallel_cpu_pct": self.parallel_cpu_pct,
            "sequential_memory_mb": self.sequential_memory_mb,
            "parallel_memory_mb": self.parallel_memory_mb,
            "equivalence_status": self.equivalence_status,
            "mismatch_count": self.mismatch_count,
            "mismatch_details": self.mismatch_details[:10],
        }
