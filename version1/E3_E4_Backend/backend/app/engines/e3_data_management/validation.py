"""Checks one record before it is written. Bad records are rejected, not crashed on."""
import ipaddress
from datetime import datetime, timezone

TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def to_utc_text(value) -> str:
    """Turn a Zeek epoch number, datetime or ISO text into one fixed UTC text format.
    A fixed format means text comparison == time comparison, so range searches use the index."""
    if isinstance(value, bool):
        raise ValueError("bad timestamp")
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    elif isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            raise ValueError(f"bad timestamp '{value}'") from None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    else:
        raise ValueError("bad timestamp")
    return dt.astimezone(timezone.utc).strftime(TS_FORMAT)


def _ip(name, value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        raise ValueError(f"{name} is not a valid IPv4/IPv6 address") from None


def _opt_int(name, value, lo=0, hi=None):
    if value is None:                       # unknown stays unknown, never 0
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a whole number or empty")
    if value < lo or (hi is not None and value > hi):
        raise ValueError(f"{name} out of range")
    return value


def _opt_float(name, value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{name} must be a number >= 0 or empty")
    return float(value)


def validate_event(e: dict, run_id: str, conn_states: set) -> tuple:
    """Returns the cleaned row (protocol still as text) or raises ValueError with the reason."""
    if not e.get("event_id"):
        raise ValueError("event_id is missing")
    if "event_timestamp" not in e or e["event_timestamp"] is None:
        raise ValueError("event_timestamp is missing")
    proto = e.get("protocol")
    proto = proto.strip().lower() if isinstance(proto, str) and proto.strip() else None
    state = e.get("conn_state")
    if state is not None and state not in conn_states:
        raise ValueError(f"unknown connection state '{state}'")

    uid = str(e["uid"]) if e.get("uid") is not None else None
    history = str(e["history"]) if e.get("history") is not None else None

    log_source = str(e["log_source"]) if e.get("log_source") is not None else "conn"
    weird_name = str(e["weird_name"]) if e.get("weird_name") is not None else None
    notice_type = str(e["notice_type"]) if e.get("notice_type") is not None else None

    return (
        str(e["event_id"]), run_id, to_utc_text(e["event_timestamp"]),
        _ip("source_ip", e.get("source_ip")), _opt_int("source_port", e.get("source_port"), 0, 65535),
        _ip("destination_ip", e.get("destination_ip")), _opt_int("destination_port", e.get("destination_port"), 0, 65535),
        proto, state, e.get("service"),
        _opt_float("duration", e.get("duration")),
        _opt_int("orig_bytes", e.get("orig_bytes")), _opt_int("resp_bytes", e.get("resp_bytes")),
        _opt_int("orig_pkts", e.get("orig_pkts")), _opt_int("resp_pkts", e.get("resp_pkts")),
        uid, history,
        _opt_int("total_bytes", e.get("total_bytes")),
        _opt_int("total_packets", e.get("total_packets")),
        _opt_float("bytes_per_packet", e.get("bytes_per_packet")),
        _opt_float("orig_to_resp_ratio", e.get("orig_to_resp_ratio")),
        log_source, weird_name, notice_type,
        _opt_float("percent_lost", e.get("percent_lost")),
        _opt_int("acks", e.get("acks")),
    )
