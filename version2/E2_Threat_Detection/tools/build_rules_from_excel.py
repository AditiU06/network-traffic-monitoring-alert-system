"""Reads the team's Excel threat sheet and writes e2_engine/rules/rules.json.

Severity/priority, names, trigger text come straight from the Excel. The Excel only
holds *text* conditions, so this script attaches the machine-readable detector for
each row (SPECS below). If a row has no spec the script STOPS - so no rule can be
silently skipped.   Usage:  python tools/build_rules_from_excel.py
"""
import json
import os
import sys

import openpyxl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XLSX = os.path.join(ROOT, "e2_engine", "rules", "zeek_network_transport_alerts.xlsx")
OUT = os.path.join(ROOT, "e2_engine", "rules", "rules.json")

# conn_states treated as a "failed connection" for scan rules.  CONFIRM: Zeek's own scan.zeek
# counts only REJ-style failures; S0 (no reply) is added here so filtered-port scans are caught.
FAILED = ["S0", "REJ", "RSTOS0"]
ICMP = ["icmp", "icmp6", "icmpv6"]


def label(*names):
    return {"type": "label", "labels": list(names)}


def weird(name):
    return label(f"Weird::Activity - {name}", name)


SPECS = {
    1: [{"type": "window_unique",
         "filter": {"proto": "tcp", "conn_state": {"in": FAILED}},
         "group_by": ["src_ip", "dst_port"], "unique_field": "dst_ip",
         "window_sec": 300, "threshold": 25, "op": "gt", "report": ["src_ip", "dst_port"]},
        label("Scan::Address_Scan")],
    2: [{"type": "window_unique",
         "filter": {"proto": "tcp", "conn_state": {"in": FAILED}},
         "group_by": ["src_ip", "dst_ip"], "unique_field": "dst_port",
         "window_sec": 300, "threshold": 15, "op": "ge", "report": ["src_ip", "dst_ip"]},
        label("Scan::Port_Scan")],
    3: [weird("fragment_overlap")], 4: [weird("fragment_inconsistency")],
    5: [weird("fragment_size_inconsistency")], 6: [weird("fragment_protocol_inconsistency")],
    7: [label("Conn::Retransmission_Inconsistency", "retransmission_inconsistency"),
        {"type": "match", "filter": {"proto": "tcp", "history": {"contains": "r"}}}],
    8: [weird("FIN_storm")], 9: [weird("SYN_after_partial")],
    10: [weird("TCP_christmas"),
         {"type": "match", "filter": {"proto": "tcp", "tcp_flags": {"has_all": "FUP"}}}],
    11: [weird("SYN_with_data")], 12: [weird("RST_storm")],
    13: [label("Conn::Content_Gap", "content_gap"),
         {"type": "match", "filter": {"proto": "tcp", "history": {"contains": "c"}}}],
    14: [{"type": "window_combo", "window_sec": 180, "components": [
             {"filter": {"ttl": {"lt": 10}}, "key_fields": ["src_ip"], "key_as": ["src_ip"], "min_count": 1},
             {"filter": {"proto": ICMP, "icmp_type": {"in": [11, 3]}},   # 11 = ICMPv4, 3 = ICMPv6 Time Exceeded
              "key_fields": ["dst_ip"], "key_as": ["src_ip"], "min_count": 3}]},
         label("Traceroute::Detected")],
    15: [weird("connection_originator_SYN_ack")], 16: [weird("repeated_SYN_with_ack")],
    17: [weird("repeated_SYN_reply_wo_ack")], 18: [weird("active_connection_reuse")],
    19: [weird("premature_connection_reuse")], 20: [weird("data_before_established")],
    21: [weird("inappropriate_FIN")], 22: [weird("window_recision")],
    23: [weird("SYN_seq_jump")], 24: [weird("fragment_with_DF")], 25: [weird("truncated_IP")],
    26: [label("DPD::Protocol_Found", "ProtocolDetector::Protocol_Found")],
    27: [label("DPD::Server_Found", "ProtocolDetector::Server_Found")],
    28: [{"type": "log_source", "sources": ["tunnel"]}, label("Tunnel activity")],
    29: [{"type": "match", "filter": {"log_source": "capture_loss", "percent_lost": {"gt": 10}}},
         label("CaptureLoss::Too_Much_Loss")],
    30: [{"type": "match", "filter": {"log_source": "capture_loss", "acks": {"lt": 1}}},
         label("CaptureLoss::Too_Little_Traffic")],
    31: [weird("bad_IP_checksum"), {"type": "match", "filter": {"ip_checksum_valid": False}}],
    32: [weird("bad_TCP_checksum"), {"type": "match", "filter": {"proto": "tcp", "checksum_valid": False}}],
    33: [weird("bad_UDP_checksum"), {"type": "match", "filter": {"proto": "udp", "checksum_valid": False}}],
    34: [weird("bad_ICMP_checksum"), {"type": "match", "filter": {"proto": ICMP, "checksum_valid": False}}],
    35: [weird("possible_split_routing")], 36: [weird("above_hole_data_without_any_acks")],
    37: [weird("excessive_data_without_further_acks")],
    38: [{"type": "log_source", "sources": ["known_hosts", "known_services"]},
         label("New host / new service")],
}

# Rules the project documents (FR-04) require but the Excel does not contain.
# ALL values are PROPOSED DEFAULTS - confirm with the team, then edit here and re-run.
SUPPLEMENTARY = [
    {"rule_id": "S01", "name": "SYN flood", "severity": "HIGH",
     "trigger_text": "100 or more SYN-only connection attempts from one source to one destination port within 10 s",
     "indicates": "Denial of service by SYN flooding",
     "detectors": [
         {"type": "window_combo", "window_sec": 10, "components": [
             {"filter": {"proto": "tcp", "tcp_flags": {"equals_any": ["S"]}},
              "key_fields": ["src_ip", "dst_ip", "dst_port"], "min_count": 100}]},
         {"type": "window_combo", "window_sec": 10, "components": [
             {"filter": {"proto": "tcp", "conn_state": "S0"},
              "key_fields": ["src_ip", "dst_ip", "dst_port"], "min_count": 100}]}]},
    {"rule_id": "S02", "name": "ICMP sweep", "severity": "MEDIUM",
     "trigger_text": "ICMP echo requests from one source to 10 or more unique hosts within 60 s",
     "indicates": "Host discovery / network mapping",
     "detectors": [{"type": "window_unique",
                    "filter": {"proto": ICMP, "icmp_type": {"in": [8, 128], "or_missing": True}},
                    "group_by": ["src_ip"], "unique_field": "dst_ip",
                    "window_sec": 60, "threshold": 10, "op": "ge"}]},
    {"rule_id": "S03", "name": "ICMP ping flood", "severity": "HIGH",
     "trigger_text": "100 or more ICMP echo requests from one source to one destination within 10 s",
     "indicates": "ICMP denial of service",
     "detectors": [{"type": "window_combo", "window_sec": 10, "components": [
         {"filter": {"proto": ICMP, "icmp_type": {"in": [8, 128], "or_missing": True}},
          "key_fields": ["src_ip", "dst_ip"], "min_count": 100}]}]},
    {"rule_id": "S04", "name": "Abnormal TCP flag pattern", "severity": "HIGH",
     "trigger_text": "TCP packet with NULL flags, SYN+FIN or SYN+RST (Xmas is covered by the Excel rule R10)",
     "indicates": "Stealth scan or crafted packets. Only valid if tcp_flags are per-packet, not a union over the connection",
     "detectors": [{"type": "match", "filter": {"proto": "tcp", "tcp_flags": {"equals_any": ["NONE", "SF", "SR"]}}}]},
    {"rule_id": "S05", "name": "Weak or outdated TLS version", "severity": "MEDIUM",
     "trigger_text": "TLS/SSL handshake using SSLv2, SSLv3, TLSv1.0 or TLSv1.1",
     "indicates": "Deprecated protocol version, downgrade or legacy client/server",
     "detectors": [{"type": "match", "filter": {"tls_version": {"in": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]}}}]},
    {"rule_id": "S06", "name": "Blacklisted IP address", "severity": "HIGH",
     "trigger_text": "Source or destination IPv4/IPv6 address is in the blacklist",
     "indicates": "Communication with a known-bad host",
     "detectors": [{"type": "blacklist"}]},
    {"rule_id": "S07", "name": "High Volume / DoS Traffic Anomaly", "severity": "HIGH",
     "trigger_text": "Originator transmits abnormally high volume (> 50,000 bytes or > 1,000 packets) with 0 response bytes or unestablished connection",
     "indicates": "Data exfiltration attempt, UDP/TCP flood, or amplification denial of service",
     "detectors": [
         {"type": "match", "filter": {"orig_bytes": {"gt": 50000}, "resp_bytes": {"eq": 0}}},
         {"type": "match", "filter": {"orig_pkts": {"gt": 1000}, "resp_pkts": {"eq": 0}}},
     ]},
]


def main():
    ws = openpyxl.load_workbook(XLSX, read_only=True)["Alerts"]
    rows = [r for r in ws.iter_rows(min_row=2, values_only=True) if r[0] is not None]
    rules, missing = [], []
    for no, prio, alert, src, script, trig, ind, default in rows:
        if no not in SPECS:
            missing.append(no)
            continue
        rules.append({"rule_id": f"R{int(no):02d}", "name": alert, "severity": str(prio).upper(),
                      "origin": "excel", "excel_no": int(no), "log_source": src,
                      "zeek_script": script, "trigger_text": trig, "indicates": ind,
                      "default_behavior": default, "detectors": SPECS[no]})
    if missing:
        sys.exit(f"ERROR: Excel rows without a machine-readable spec: {missing}")
    for s in SUPPLEMENTARY:
        s.update(origin="supplementary", log_source="(not in Excel)",
                 note="PROPOSED DEFAULT - not in the Excel sheet; confirm with team")
        rules.append(s)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"generated_from": os.path.basename(XLSX), "rules": rules}, fh, indent=2)
    print(f"wrote {len(rules)} rules ({len(rows)} from Excel + {len(SUPPLEMENTARY)} supplementary) -> {OUT}")


if __name__ == "__main__":
    main()
