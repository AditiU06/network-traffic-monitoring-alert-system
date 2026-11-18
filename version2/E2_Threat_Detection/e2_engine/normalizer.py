"""Turns a raw record (dict) from E3 into a NetEvent.

E3's real column names were not available, so ALIASES lists every name we accept
for each field. After you see E3's schema, add its names here - this is the ONLY
place field names are mapped.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .models import NetEvent


class EventValidationError(ValueError):
    pass


ALIASES = {
    "event_id": ["event_id", "id", "eventId"],
    "run_id": ["run_id", "runId"],
    "ts": ["event_timestamp", "ts", "timestamp", "time", "event_time"],
    "log_source": ["log_source", "log_type", "source_log", "_path", "log"],
    "proto": ["protocol_name", "proto", "protocol"],
    "src_ip": ["src_ip", "source_ip", "id.orig_h", "orig_h", "id_orig_h"],
    "src_port": ["src_port", "source_port", "id.orig_p", "orig_p", "id_orig_p"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "id.resp_h", "resp_h", "id_resp_h"],
    "dst_port": ["dst_port", "dest_port", "destination_port", "id.resp_p", "resp_p", "id_resp_p"],
    "conn_state": ["conn_state_code", "conn_state", "state", "tcp_state"],
    "tcp_flags": ["tcp_flags", "flags"],
    "ttl": ["ttl"],
    "icmp_type": ["icmp_type"],
    "checksum_valid": ["checksum_valid", "checksum_ok", "checksum_status", "checksum"],
    "ip_checksum_valid": ["ip_checksum_valid", "ip_checksum_ok"],
    "tls_version": ["tls_version", "ssl_version", "version"],
    "weird_name": ["weird_name", "weird"],
    "notice_type": ["notice_type", "note"],
    "percent_lost": ["percent_lost", "pct_lost"],
    "acks": ["acks"],
    "history": ["history", "conn_history"],
    "orig_bytes": ["orig_bytes", "origBytes"],
    "resp_bytes": ["resp_bytes", "respBytes"],
    "orig_pkts": ["orig_pkts", "origPkts", "orig_packets"],
    "resp_pkts": ["resp_pkts", "respPkts", "resp_packets"],
}

_MISSING = (None, "", "-", "(empty)")
_FLAG_NAMES = {"FIN": "F", "SYN": "S", "RST": "R", "PSH": "P", "PUSH": "P", "ACK": "A", "URG": "U"}
_FLAG_BITS = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U")]
_TRUE = {"true", "ok", "valid", "good", "pass", "passed", "1", "yes"}
_FALSE = {"false", "bad", "invalid", "fail", "failed", "error", "0", "no"}


def _pick(raw: Mapping, field: str):
    for name in ALIASES[field]:
        if name in raw and raw[name] not in _MISSING:
            return raw[name]
    return None


def parse_ts(v) -> float:
    if isinstance(v, bool):
        raise EventValidationError(f"invalid timestamp: {v!r}")
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).timestamp()
    s = str(v).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        raise EventValidationError(f"invalid timestamp: {v!r}")


def parse_ip(v, name) -> Optional[str]:
    if v in _MISSING:
        return None
    try:
        return ipaddress.ip_address(str(v).strip()).compressed
    except ValueError:
        raise EventValidationError(f"invalid {name}: {v!r}")


def parse_port(v, name) -> Optional[int]:
    if v in _MISSING:
        return None
    try:
        p = int(v)
    except (TypeError, ValueError):
        raise EventValidationError(f"invalid {name}: {v!r}")
    if not 0 <= p <= 65535:
        raise EventValidationError(f"{name} out of range: {v!r}")
    return p


def _opt_int(v):
    try:
        return None if v in _MISSING else int(float(v))
    except (TypeError, ValueError):
        return None


def _opt_float(v):
    try:
        return None if v in _MISSING else float(v)
    except (TypeError, ValueError):
        return None


def parse_bool(v) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if v in _MISSING:
        return None
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return None


def parse_flags(v):
    """Accepts 'FUP', 'SYN,ACK', ['SYN'], 0x29, 41, 'NONE'. Returns frozenset of
    letters, empty set (= NULL flags) or None (= unknown)."""
    if v in _MISSING:
        return None
    if isinstance(v, (set, frozenset, list, tuple)):
        out = set()
        for item in v:
            f = parse_flags(item)
            if f is None:
                return None
            out |= f
        return frozenset(out)
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return frozenset(l for bit, l in _FLAG_BITS if v & bit)
    s = str(v).strip().upper()
    if s in ("NONE", "NULL"):
        return frozenset()
    tokens = [t for t in re.split(r"[,|+\s]+", s) if t]
    if tokens and all(t in _FLAG_NAMES for t in tokens):
        return frozenset(_FLAG_NAMES[t] for t in tokens)
    if re.fullmatch(r"0X[0-9A-F]+", s):
        return parse_flags(int(s, 16))
    if s.isdigit():
        return parse_flags(int(s))
    if re.fullmatch(r"[FSRPAU]+", s):
        return frozenset(s)
    return None


def parse_tls(v) -> Optional[str]:
    if v in _MISSING:
        return None
    s = re.sub(r"[\s_]", "", str(v)).upper()
    m = re.fullmatch(r"(SSL|TLS)V?(\d)\.?(\d)?", s)
    if not m:
        return str(v).strip()
    fam, major, minor = m.groups()
    if fam == "SSL":
        return f"SSLv{major}"
    return f"TLSv{major}.{minor or '0'}"


def _labels(weird, notice):
    out = set()
    for v in (weird, notice):
        if v in _MISSING:
            continue
        s = str(v).strip().lower()
        out.add(s)
        prefix = "weird::activity - "
        if s.startswith(prefix):
            out.add(s[len(prefix):])
    return frozenset(out)


def normalize_event(raw: Any, default_run_id: Optional[str] = None) -> NetEvent:
    if isinstance(raw, NetEvent):
        return raw
    if not isinstance(raw, Mapping):
        raise EventValidationError(f"record is not a mapping: {type(raw).__name__}")
    event_id = _pick(raw, "event_id")
    if event_id is None:
        raise EventValidationError("missing event_id")
    ts_raw = _pick(raw, "ts")
    if ts_raw is None:
        raise EventValidationError(f"event {event_id}: missing timestamp")
    try:
        ts = parse_ts(ts_raw)
        src_ip = parse_ip(_pick(raw, "src_ip"), "src_ip")
        dst_ip = parse_ip(_pick(raw, "dst_ip"), "dst_ip")
        src_port = parse_port(_pick(raw, "src_port"), "src_port")
        dst_port = parse_port(_pick(raw, "dst_port"), "dst_port")
    except EventValidationError as exc:
        raise EventValidationError(f"event {event_id}: {exc}")

    log_source = _pick(raw, "log_source")
    if log_source is not None:
        log_source = str(log_source).strip().lower()
        if log_source.endswith(".log"):
            log_source = log_source[:-4]
    weird = _pick(raw, "weird_name")
    if weird is None and log_source == "weird" and raw.get("name") not in _MISSING:
        weird = raw.get("name")
    proto = _pick(raw, "proto")
    state = _pick(raw, "conn_state")
    return NetEvent(
        event_id=event_id,
        ts=ts,
        run_id=_pick(raw, "run_id") or default_run_id,
        log_source=log_source,
        proto=str(proto).strip().lower() if proto is not None else None,
        src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
        conn_state=str(state).strip().upper() if state is not None else None,
        tcp_flags=parse_flags(_pick(raw, "tcp_flags")),
        ttl=_opt_int(_pick(raw, "ttl")),
        icmp_type=_opt_int(_pick(raw, "icmp_type")),
        checksum_valid=parse_bool(_pick(raw, "checksum_valid")),
        ip_checksum_valid=parse_bool(_pick(raw, "ip_checksum_valid")),
        tls_version=parse_tls(_pick(raw, "tls_version")),
        percent_lost=_opt_float(_pick(raw, "percent_lost")),
        acks=_opt_int(_pick(raw, "acks")),
        history=str(_pick(raw, "history")).strip() if _pick(raw, "history") is not None else None,
        orig_bytes=_opt_int(_pick(raw, "orig_bytes")),
        resp_bytes=_opt_int(_pick(raw, "resp_bytes")),
        orig_pkts=_opt_int(_pick(raw, "orig_pkts")),
        resp_pkts=_opt_int(_pick(raw, "resp_pkts")),
        labels=_labels(weird, _pick(raw, "notice_type")),
    )
