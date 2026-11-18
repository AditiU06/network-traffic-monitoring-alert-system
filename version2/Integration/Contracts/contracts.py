"""Shared Data Contracts and Schema Mappings across E1, E2, E3, and E4.

This module defines:
- Typed representations for E1 processed events and benchmark metrics.
- Enums for processing run statuses and execution modes.
- Field mappings between E1 and E3.
- Field mappings between E3 and E2.
- Standardized error representations.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class RunStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RunMode(str, Enum):
    SEQUENTIAL = "SEQUENTIAL"
    MULTITHREADED = "MULTITHREADED"
    BENCHMARK = "BENCHMARK"


class TransportProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class E1ProcessedEvent(BaseModel):
    """Event output format emitted by E1 in JSON or NDJSON stream."""
    record_ordinal: int = Field(ge=0, description="0-based monotonic record index")
    timestamp: str = Field(description="ISO-8601 UTC timestamp")
    uid: str = Field(description="Zeek unique connection identifier")
    source_ip: str
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_ip: str
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, description="tcp, udp, or icmp")
    service: Optional[str] = None
    duration: Optional[float] = Field(default=None, ge=0.0)
    orig_bytes: Optional[int] = Field(default=None, ge=0)
    resp_bytes: Optional[int] = Field(default=None, ge=0)
    conn_state: Optional[str] = None
    history: Optional[str] = None
    orig_pkts: Optional[int] = Field(default=None, ge=0)
    resp_pkts: Optional[int] = Field(default=None, ge=0)

    # Calculated enrichment fields from E1 EventTransformer
    total_bytes: Optional[int] = Field(default=None, ge=0)
    total_packets: Optional[int] = Field(default=None, ge=0)
    bytes_per_packet: Optional[float] = Field(default=None, ge=0.0)
    orig_to_resp_ratio: Optional[float] = Field(default=None, ge=0.0)

    # Multi-format Zeek log indicators
    log_source: Optional[str] = Field(default="conn")
    weird_name: Optional[str] = None
    notice_type: Optional[str] = None
    percent_lost: Optional[float] = None
    acks: Optional[int] = None


class E1BenchmarkMetrics(BaseModel):
    """Benchmark metrics output format emitted by E1 in JSON."""
    record_count: int = Field(ge=1)
    worker_count: int = Field(ge=1, le=16)
    sequential_duration_ms: float = Field(ge=0.0)
    multithreaded_duration_ms: float = Field(ge=0.0)
    sequential_throughput: float = Field(ge=0.0)
    multithreaded_throughput: float = Field(ge=0.0)
    speedup: Optional[float] = Field(default=None, ge=0.0)
    sequential_cpu_load: Optional[float] = Field(default=None, ge=0.0)
    multithreaded_cpu_load: Optional[float] = Field(default=None, ge=0.0)
    sequential_observed_heap_bytes: int = Field(default=0, ge=0)
    multithreaded_observed_heap_bytes: int = Field(default=0, ge=0)
    output_parity: bool = Field(default=True)


class ErrorDetails(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class StandardErrorResponse(BaseModel):
    error: ErrorDetails


def e1_to_e3_event(e1_dict: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    """
    Transforms an E1 processed event dict into an E3 database record dictionary,
    preserving UID, TCP history flags, connection fields, and E1 calculated metrics.
    """
    ordinal = e1_dict.get("record_ordinal", 0)
    event_id = e1_dict.get("event_id") or f"{run_id}-{ordinal}"

    return {
        "event_id": str(event_id),
        "run_id": str(run_id),
        "event_timestamp": e1_dict["timestamp"],
        "source_ip": e1_dict.get("source_ip"),
        "source_port": e1_dict.get("source_port"),
        "destination_ip": e1_dict.get("destination_ip"),
        "destination_port": e1_dict.get("destination_port"),
        "protocol": str(e1_dict.get("protocol", "")).lower() if e1_dict.get("protocol") else None,
        "conn_state": e1_dict.get("conn_state"),
        "service": e1_dict.get("service"),
        "duration": e1_dict.get("duration"),
        "orig_bytes": e1_dict.get("orig_bytes"),
        "resp_bytes": e1_dict.get("resp_bytes"),
        "orig_pkts": e1_dict.get("orig_pkts"),
        "resp_pkts": e1_dict.get("resp_pkts"),
        # Preserved attributes
        "uid": e1_dict.get("uid"),
        "history": e1_dict.get("history"),
        "total_bytes": e1_dict.get("total_bytes"),
        "total_packets": e1_dict.get("total_packets"),
        "bytes_per_packet": e1_dict.get("bytes_per_packet"),
        "orig_to_resp_ratio": e1_dict.get("orig_to_resp_ratio"),
        # Multi-format Zeek threat attributes
        "log_source": e1_dict.get("log_source", "conn"),
        "weird_name": e1_dict.get("weird_name"),
        "notice_type": e1_dict.get("notice_type"),
        "percent_lost": e1_dict.get("percent_lost"),
        "acks": e1_dict.get("acks"),
    }


def e1_benchmark_to_e3_performance(
    b: Dict[str, Any],
    run_id: str
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Transforms E1 BenchmarkMetrics into E3's `performance_metric` rows
    and `benchmark_comparison` record.
    """
    seq_time_sec = float(b.get("sequential_duration_ms", 0.0)) / 1000.0
    mt_time_sec = float(b.get("multithreaded_duration_ms", 0.0)) / 1000.0
    workers = int(b.get("worker_count", 1))

    seq_heap_mb = round(float(b.get("sequential_observed_heap_bytes", 0)) / (1024.0 * 1024.0), 2)
    mt_heap_mb = round(float(b.get("multithreaded_observed_heap_bytes", 0)) / (1024.0 * 1024.0), 2)

    metrics = [
        {
            "execution_mode": "SEQUENTIAL",
            "worker_count": 1,
            "execution_time_sec": max(seq_time_sec, 1e-9),
            "throughput_rec_sec": float(b.get("sequential_throughput", 0.0)),
            "cpu_usage_pct": b.get("sequential_cpu_load"),
            "peak_memory_mb": seq_heap_mb,
        },
        {
            "execution_mode": "MULTITHREADED",
            "worker_count": workers,
            "execution_time_sec": max(mt_time_sec, 1e-9),
            "throughput_rec_sec": float(b.get("multithreaded_throughput", 0.0)),
            "cpu_usage_pct": b.get("multithreaded_cpu_load"),
            "peak_memory_mb": mt_heap_mb,
        }
    ]

    parity = bool(b.get("output_parity", True))
    speedup = b.get("speedup")
    if speedup is None and mt_time_sec > 0:
        speedup = round(seq_time_sec / mt_time_sec, 2)

    comparison = {
        "speedup_ratio": speedup,
        "equivalence_status": "PASS" if parity else "FAIL",
        "mismatch_count": 0 if parity else 1,
    }

    return metrics, comparison


def e3_to_e2_event(e3_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pass-through mapper ensuring event fields from E3 are compatible with E2 normalizer aliases.
    """
    return e3_dict
