"""Plain data classes shared by all E2 modules."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, FrozenSet, List, Optional


class Severity(IntEnum):
    """Higher number = more urgent. The number doubles as the alert *priority*."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value) -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}")


@dataclass
class NetEvent:
    """One parsed network record, after E2 has normalised E3's field names."""
    event_id: Any
    ts: float
    run_id: Optional[str] = None
    log_source: Optional[str] = None
    proto: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    conn_state: Optional[str] = None
    tcp_flags: Optional[FrozenSet[str]] = None      # letters from F S R P A U
    ttl: Optional[int] = None
    icmp_type: Optional[int] = None
    checksum_valid: Optional[bool] = None           # TCP/UDP/ICMP checksum
    ip_checksum_valid: Optional[bool] = None
    tls_version: Optional[str] = None
    percent_lost: Optional[float] = None            # capture_loss.log
    acks: Optional[int] = None                      # capture_loss.log
    history: Optional[str] = None                   # Zeek conn.log history (e.g. ShADFfa, Sr, S0)
    orig_bytes: Optional[int] = None                # payload bytes from originator
    resp_bytes: Optional[int] = None                # payload bytes from responder
    orig_pkts: Optional[int] = None                 # packet count from originator
    resp_pkts: Optional[int] = None                 # packet count from responder
    labels: FrozenSet[str] = frozenset()            # lower-case weird / notice names


@dataclass
class Rule:
    rule_id: str
    name: str
    severity: Severity
    priority: int
    origin: str                      # "excel" or "supplementary"
    log_source: str
    trigger_text: str
    indicates: str
    detectors: List[Dict[str, Any]]
    cooldown_sec: Optional[float] = None
    enabled: bool = True
    note: str = ""


@dataclass
class Hit:
    """A detector says 'this rule fired'. The engine turns a Hit into an Alert
    (after cooldown suppression)."""
    rule: Rule
    detail: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    related_event_ids: List[Any]
    trigger_event_id: Any
    event_time: float


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    alert_type: str
    description: str
    severity: str
    priority: int
    detected_at: str                 # wall-clock time the alert was created (ISO-8601 UTC)
    event_time: float                # timestamp of the event that completed the condition
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    related_event_ids: List[Any]
    run_id: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "alert_type": self.alert_type,
            "description": self.description,
            "severity": self.severity,
            "priority": self.priority,
            "detected_at": self.detected_at,
            "event_time": self.event_time,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "related_event_ids": list(self.related_event_ids),
            "run_id": self.run_id,
        }

    def fingerprint(self):
        """Run-independent identity used to compare sequential vs multithreaded
        results (NFR-03). Excludes alert_id, run_id and detected_at."""
        return (self.rule_id, self.severity, self.priority, self.event_time,
                self.source_ip, self.destination_ip, self.source_port,
                self.destination_port, tuple(map(str, self.related_event_ids)))


def make_alert_id(run_id, rule_id, src_ip, trigger_event_id) -> str:
    """Deterministic: the same run + rule + IP + trigger event always gives the
    same ID, so a retry or a re-run produces the *same* alert, which E3 can
    recognise and ignore instead of storing twice."""
    raw = f"{run_id}|{rule_id}|{src_ip}|{trigger_event_id}"
    return "ALR-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16].upper()


@dataclass
class DetectionSummary:
    run_id: Optional[str] = None
    total_events_received: int = 0
    events_evaluated: int = 0
    rules_loaded: int = 0
    rules_evaluated: int = 0          # active rules applied to every event
    rule_checks: int = 0              # individual detector evaluations performed
    alerts_generated: int = 0
    alerts_suppressed: int = 0
    alerts_sent: int = 0
    alerts_duplicate_at_e3: int = 0
    alerts_pending: int = 0           # generated but not yet stored (E3 failure)
    errors: int = 0
    error_samples: List[str] = field(default_factory=list)
    alerts_by_severity: Dict[str, int] = field(default_factory=dict)
    alerts_by_rule: Dict[str, int] = field(default_factory=dict)
    rules_without_eligible_data: List[str] = field(default_factory=list)
    duration_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)
