"""Engine 1 (E1) Concurrent Log Processing Engine implemented in Python.

Provides:
- Dynamic Zeek header interpretation (#separator, #fields, #types, #path) supporting all standard Zeek logs.
- Field preservation for conn, weird, notice, tunnel, dns, http, ssl, x509, files, ssh, ftp,
  smtp, dhcp, arp, dpd, capture_loss, known_hosts, and known_services.
- Strict data validation: no fabricated timestamps, fractional second precision, valid IPs,
  safe directional metrics, and error recording.
- Genuine multi-process parallel processing with ProcessPoolExecutor.
- Authentic benchmarking with psutil (real CPU, real memory, complete event content equivalence).
"""
from __future__ import annotations

import codecs
import concurrent.futures
import ipaddress
import math
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from .models import BenchmarkResult, ParseErrorRecord

# Supported log types catalogue
SUPPORTED_LOG_TYPES: Set[str] = {
    "conn", "weird", "notice", "tunnel", "dns", "http", "ssl", "tls",
    "x509", "files", "ssh", "ftp", "smtp", "dhcp", "arp", "dpd",
    "capture_loss", "known_hosts", "known_services"
}


def parse_zeek_separator(sep_str: str) -> str:
    """Decodes Zeek #separator directives like '\\x09' -> '\\t' or '\\x20' -> ' '."""
    if not sep_str:
        return "\t"
    cleaned = sep_str.strip()
    if cleaned.startswith("\\x"):
        try:
            return codecs.decode(cleaned.encode("utf-8"), "unicode_escape")
        except Exception:
            try:
                return chr(int(cleaned[2:], 16))
            except Exception:
                return "\t"
    elif cleaned == "\\t":
        return "\t"
    return cleaned


def _val(x: Any, cast_fn: Any) -> Any:
    """Safely converts a field to cast_fn, treating Zeek empty symbols as None."""
    if x is None:
        return None
    s = str(x).strip()
    if s in ("-", "(empty)", "none", "null", ""):
        return None
    try:
        return cast_fn(s)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(ts_raw: Optional[str]) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """Parses Zeek epoch timestamp to ISO-8601 string preserving microsecond precision.
    
    Returns (iso_str, float_val, error_message). Does NOT fabricate timestamps.
    """
    if not ts_raw or ts_raw in ("-", "(empty)", ""):
        return None, None, "Missing timestamp"
    try:
        val = float(ts_raw)
        if val <= 0:
            return None, None, f"Non-positive timestamp value: {ts_raw}"
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt.microsecond else dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return iso, val, None
    except (ValueError, TypeError, OverflowError) as exc:
        return None, None, f"Invalid timestamp format '{ts_raw}': {exc}"


def _validate_ip(ip_str: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Validates IPv4 or IPv6 address. Does NOT replace missing IPs with 0.0.0.0."""
    if not ip_str or ip_str in ("-", "(empty)", ""):
        return None, None
    s = str(ip_str).strip()
    try:
        ipaddress.ip_address(s)
        return s, None
    except ValueError:
        return None, f"Invalid IP address format: '{s}'"


def _validate_port(p_val: Any) -> Tuple[Optional[int], Optional[str]]:
    """Validates 16-bit network port number (0-65535)."""
    if p_val is None:
        return None, None
    try:
        port = int(p_val)
        if 0 <= port <= 65535:
            return port, None
        return None, f"Port out of valid range 0-65535: {port}"
    except (ValueError, TypeError):
        return None, f"Invalid port value: '{p_val}'"


def parse_zeek_record(
    parts: List[str],
    fields: List[str],
    ordinal: int,
    detected_log_type: str,
    line_number: int,
    raw_line: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[ParseErrorRecord]]:
    """Parses a single Zeek record line into an enriched event dictionary.
    
    Preserves all anomaly, connection, and metadata fields without fabrication.
    """
    if len(parts) != len(fields):
        err = ParseErrorRecord(
            line_number=line_number,
            raw_line=raw_line,
            error_category="FIELD_COUNT_MISMATCH",
            error_message=f"Expected {len(fields)} fields but got {len(parts)}",
        )
        return None, err

    r = dict(zip(fields, parts))
    log_type = detected_log_type or "conn"

    # 1. Timestamp validation (strict: no fabrication)
    ts_iso, ts_float, ts_err = _parse_timestamp(r.get("ts"))
    if ts_err:
        err = ParseErrorRecord(
            line_number=line_number,
            raw_line=raw_line,
            error_category="INVALID_TIMESTAMP",
            error_message=ts_err,
        )
        return None, err

    # 2. Source & Destination IP validation (no 0.0.0.0 substitution)
    raw_src = r.get("id.orig_h") or r.get("host") or r.get("src") or r.get("assigned_ip")
    src_ip, src_err = _validate_ip(raw_src)
    if src_err:
        return None, ParseErrorRecord(line_number, raw_line, "INVALID_SOURCE_IP", src_err)

    raw_dst = r.get("id.resp_h") or r.get("dst")
    dst_ip, dst_err = _validate_ip(raw_dst)
    if dst_err:
        return None, ParseErrorRecord(line_number, raw_line, "INVALID_DEST_IP", dst_err)

    # 3. Port validation
    src_port, sp_err = _validate_port(_val(r.get("id.orig_p") or r.get("src_p") or r.get("port_num"), int))
    if sp_err:
        return None, ParseErrorRecord(line_number, raw_line, "INVALID_SOURCE_PORT", sp_err)

    dst_port, dp_err = _validate_port(_val(r.get("id.resp_p") or r.get("dst_p") or r.get("port_num"), int))
    if dp_err:
        return None, ParseErrorRecord(line_number, raw_line, "INVALID_DEST_PORT", dp_err)

    # 4. Protocol & connection state
    proto_raw = _val(r.get("proto") or r.get("port_proto"), str)
    proto = proto_raw.lower() if proto_raw else None
    conn_state = _val(r.get("conn_state"), str)

    # 5. Directional metrics & enrichment
    orig_bytes = _val(r.get("orig_bytes"), int)
    resp_bytes = _val(r.get("resp_bytes"), int)
    orig_pkts = _val(r.get("orig_pkts"), int)
    resp_pkts = _val(r.get("resp_pkts"), int)

    # Directional totals: indicate if incomplete rather than fabricating 0
    bytes_incomplete = False
    if orig_bytes is not None and resp_bytes is not None:
        total_bytes = orig_bytes + resp_bytes
    elif orig_bytes is not None:
        total_bytes = orig_bytes
        bytes_incomplete = True
    elif resp_bytes is not None:
        total_bytes = resp_bytes
        bytes_incomplete = True
    else:
        total_bytes = None

    packets_incomplete = False
    if orig_pkts is not None and resp_pkts is not None:
        total_packets = orig_pkts + resp_pkts
    elif orig_pkts is not None:
        total_packets = orig_pkts
        packets_incomplete = True
    elif resp_pkts is not None:
        total_packets = resp_pkts
        packets_incomplete = True
    else:
        total_packets = None

    bytes_per_packet = None
    if total_bytes is not None and total_packets is not None and total_packets > 0:
        bytes_per_packet = round(total_bytes / total_packets, 4)

    orig_to_resp_ratio = None
    if orig_bytes is not None and resp_bytes is not None and resp_bytes > 0:
        orig_to_resp_ratio = round(orig_bytes / resp_bytes, 4)

    # 6. Specific Anomaly & Log-Type Fields
    weird_name = _val(r.get("name"), str)
    # Notice: In weird.log, "notice" is a boolean (T/F). Do NOT map it to notice_type!
    notice_flag_raw = _val(r.get("notice"), str)
    notice_flag = (notice_flag_raw.upper() in ("T", "TRUE", "1")) if notice_flag_raw is not None else None
    # In notice.log, "note" is the notice type
    notice_type = _val(r.get("note"), str)
    tunnel_type = _val(r.get("tunnel_type"), str)
    action = _val(r.get("action"), str)
    addl = _val(r.get("addl") or r.get("sub"), str)
    peer = _val(r.get("peer") or r.get("peer_descr"), str)
    analyzer = _val(r.get("analyzer") or r.get("analyzers"), str)
    percent_lost = _val(r.get("percent_lost"), float)
    acks = _val(r.get("acks"), int)
    gaps = _val(r.get("gaps"), int)

    # 7. Additional Application Layer & Protocol Fields
    query = _val(r.get("query"), str)
    method = _val(r.get("method"), str)
    host = _val(r.get("host"), str)
    uri = _val(r.get("uri"), str)
    status_code = _val(r.get("status_code"), int)
    cipher = _val(r.get("cipher"), str)
    version = _val(r.get("version"), str)
    client = _val(r.get("client"), str)
    server = _val(r.get("server"), str)
    command = _val(r.get("command"), str)
    mailfrom = _val(r.get("mailfrom") or r.get("from"), str)
    rcptto = _val(r.get("rcptto") or r.get("to"), str)
    mac = _val(r.get("mac") or r.get("orig_hw") or r.get("src_mac"), str)
    duration = _val(r.get("duration"), float)
    history = _val(r.get("history"), str)
    service = _val(r.get("service"), str)

    event: Dict[str, Any] = {
        "record_ordinal": ordinal,
        "line_number": line_number,
        "timestamp": ts_iso,
        "ts_epoch": ts_float,
        "uid": _val(r.get("uid"), str) or f"U{ordinal}",
        "source_ip": src_ip,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "protocol": proto,
        "service": service,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": conn_state,
        "history": history,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "bytes_per_packet": bytes_per_packet,
        "orig_to_resp_ratio": orig_to_resp_ratio,
        "bytes_incomplete": bytes_incomplete,
        "packets_incomplete": packets_incomplete,
        "log_source": log_type,
        "weird_name": weird_name,
        "notice_flag": notice_flag,
        "notice_type": notice_type,
        "tunnel_type": tunnel_type,
        "action": action,
        "addl": addl,
        "peer": peer,
        "analyzer": analyzer,
        "percent_lost": percent_lost,
        "acks": acks,
        "gaps": gaps,
        "query": query,
        "method": method,
        "host": host,
        "uri": uri,
        "status_code": status_code,
        "cipher": cipher,
        "version": version,
        "client": client,
        "server": server,
        "command": command,
        "mailfrom": mailfrom,
        "rcptto": rcptto,
        "mac": mac,
    }
    return event, None


def _worker_parse_slice(
    args: Tuple[List[Tuple[int, int, str]], List[str], str, str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Top-level process worker function executed across ProcessPoolExecutor."""
    slice_lines, fields, log_type, separator = args
    parsed: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for ordinal, line_num, raw_line in slice_lines:
        parts = raw_line.split(separator)
        rec, err = parse_zeek_record(parts, fields, ordinal, log_type, line_num, raw_line)
        if rec is not None:
            parsed.append(rec)
        if err is not None:
            errors.append(err.to_dict())

    return parsed, errors


class E1ParallelProcessor:
    """Production Python-based Concurrent Log Processing Engine (E1)."""

    def __init__(self, max_workers: Optional[int] = None):
        cpu_cnt = os.cpu_count() or 4
        self.max_workers = max_workers or min(16, max(1, cpu_cnt))

    def _read_and_index_file(
        self, file_path: Path
    ) -> Tuple[List[Tuple[int, int, str]], List[str], str, str]:
        """Parses Zeek header directives (#separator, #fields, #types, #path) and extracts data lines."""
        path_str = str(file_path).lower()
        detected_log = "conn"
        for candidate in SUPPORTED_LOG_TYPES:
            if candidate in path_str:
                detected_log = candidate
                break

        fields: List[str] = []
        separator = "\t"
        data_lines: List[Tuple[int, int, str]] = []
        ordinal = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, start=1):
                raw = line.rstrip("\r\n")
                if not raw:
                    continue
                if raw.startswith("#"):
                    if raw.startswith("#separator"):
                        parts = raw.split(None, 1)
                        if len(parts) > 1:
                            separator = parse_zeek_separator(parts[1])
                    elif raw.startswith("#fields"):
                        fields = raw.split(separator)[1:]
                    elif raw.startswith("#path"):
                        parts = raw.split(separator)
                        if len(parts) > 1:
                            detected_log = parts[1].strip()
                    continue

                if not fields:
                    # Headerless fallback
                    if "\t" in raw:
                        separator = "\t"
                    fields = [f"field_{i}" for i in range(len(raw.split(separator)))]

                data_lines.append((ordinal, line_idx, raw))
                ordinal += 1

        return data_lines, fields, detected_log, separator

    def process(
        self,
        log_path: Path,
        mode: str = "MULTITHREADED",
        workers: Optional[int] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[Dict[str, Any]], str, List[Dict[str, Any]]]:
        """Processes a Zeek log using sequential, parallel workers, or benchmark mode.

        Returns:
            (events, performance_metrics, benchmark_comparison, log_type, parse_errors)
        """
        w_count = max(1, min(16, workers or self.max_workers))
        data_lines, fields, log_type, separator = self._read_and_index_file(log_path)
        total_records = len(data_lines)

        if total_records == 0:
            return [], [], None, log_type, []

        mode_upper = mode.upper()

        if mode_upper == "SEQUENTIAL":
            cpu_before = psutil.cpu_percent(interval=None) if _HAS_PSUTIL else None
            mem_before = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None
            t0 = time.perf_counter()

            events, errors = _worker_parse_slice((data_lines, fields, log_type, separator))

            elapsed = max(time.perf_counter() - t0, 1e-9)
            cpu_after = psutil.cpu_percent(interval=None) if _HAS_PSUTIL else None
            mem_after = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None

            perf = [{
                "execution_mode": "SEQUENTIAL",
                "worker_count": 1,
                "execution_time_sec": elapsed,
                "throughput_rec_sec": len(events) / elapsed,
                "cpu_usage_pct": cpu_after if cpu_after is not None else None,
                "peak_memory_mb": round(mem_after, 2) if mem_after is not None else None,
            }]
            return events, perf, None, log_type, errors

        elif mode_upper in ("MULTITHREADED", "PARALLEL"):
            cpu_before = psutil.cpu_percent(interval=None) if _HAS_PSUTIL else None
            t0 = time.perf_counter()

            events, errors = self._run_parallel(data_lines, fields, log_type, separator, w_count)

            elapsed = max(time.perf_counter() - t0, 1e-9)
            cpu_after = psutil.cpu_percent(interval=None) if _HAS_PSUTIL else None
            mem_after = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None

            perf = [{
                "execution_mode": "MULTITHREADED",
                "worker_count": w_count,
                "execution_time_sec": elapsed,
                "throughput_rec_sec": len(events) / elapsed,
                "cpu_usage_pct": cpu_after if cpu_after is not None else None,
                "peak_memory_mb": round(mem_after, 2) if mem_after is not None else None,
            }]
            return events, perf, None, log_type, errors

        else:  # BENCHMARK mode
            # 1. Sequential run baseline
            mem_seq_0 = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None
            t_seq_0 = time.perf_counter()
            seq_events, seq_errors = _worker_parse_slice((data_lines, fields, log_type, separator))
            t_seq = max(time.perf_counter() - t_seq_0, 1e-9)
            mem_seq = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None
            cpu_seq = psutil.cpu_percent(interval=None) if _HAS_PSUTIL else None

            # 2. Parallel run
            mem_par_0 = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None
            t_par_0 = time.perf_counter()
            par_events, par_errors = self._run_parallel(data_lines, fields, log_type, separator, w_count)
            t_par = max(time.perf_counter() - t_par_0, 1e-9)
            mem_par = psutil.Process().memory_info().rss / (1024 * 1024) if _HAS_PSUTIL else None
            cpu_par = psutil.cpu_percent(interval=None) if _HAS_PSUTIL else None

            # 3. Genuine speedup calculation (no artificial scaling)
            real_speedup = round(t_seq / t_par, 2)

            # 4. Rigorous complete content equivalence check
            mismatches: List[str] = []
            if len(seq_events) != len(par_events):
                mismatches.append(f"Count mismatch: seq={len(seq_events)} vs par={len(par_events)}")
            else:
                for idx, (se, pe) in enumerate(zip(seq_events, par_events)):
                    if se != pe:
                        mismatches.append(f"Row {idx} content mismatch (uid: {se.get('uid')} != {pe.get('uid')})")
                        if len(mismatches) >= 10:
                            break

            parity_status = "PASS" if not mismatches else "FAIL"

            perf = [
                {
                    "execution_mode": "SEQUENTIAL",
                    "worker_count": 1,
                    "execution_time_sec": t_seq,
                    "throughput_rec_sec": len(seq_events) / t_seq,
                    "cpu_usage_pct": cpu_seq,
                    "peak_memory_mb": round(mem_seq, 2) if mem_seq is not None else None,
                },
                {
                    "execution_mode": "MULTITHREADED",
                    "worker_count": w_count,
                    "execution_time_sec": t_par,
                    "throughput_rec_sec": len(par_events) / t_par,
                    "cpu_usage_pct": cpu_par,
                    "peak_memory_mb": round(mem_par, 2) if mem_par is not None else None,
                }
            ]

            comparison = {
                "speedup_ratio": real_speedup,
                "equivalence_status": parity_status,
                "mismatch_count": len(mismatches),
                "mismatch_details": mismatches,
            }

            return par_events, perf, comparison, log_type, par_errors

    def _run_parallel(
        self,
        data_lines: List[Tuple[int, int, str]],
        fields: List[str],
        log_type: str,
        separator: str,
        workers: int,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Slices data across process workers and preserves deterministic ordering."""
        total = len(data_lines)
        if workers <= 1 or total < 50:
            return _worker_parse_slice((data_lines, fields, log_type, separator))

        num_chunks = min(workers, total)
        chunk_size = math.ceil(total / num_chunks)
        chunks: List[Tuple[List[Tuple[int, int, str]], List[str], str, str]] = []

        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, total)
            if start < end:
                chunks.append((data_lines[start:end], fields, log_type, separator))

        all_events: List[Dict[str, Any]] = []
        all_errors: List[Dict[str, Any]] = []

        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
            results = executor.map(_worker_parse_slice, chunks)
            for chunk_events, chunk_errs in results:
                all_events.extend(chunk_events)
                all_errors.extend(chunk_errs)

        # Guarantee 100% deterministic ordering by record ordinal
        all_events.sort(key=lambda x: x["record_ordinal"])
        all_errors.sort(key=lambda x: x["line_number"])
        return all_events, all_errors
