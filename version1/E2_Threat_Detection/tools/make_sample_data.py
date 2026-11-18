"""Writes sample_data/sample_events.jsonl: a small mixed dataset (attacks + benign traffic)."""
import json, os
out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_data", "sample_events.jsonl")
T0 = 1_760_000_000
ev, n = [], [0]
def add(dt, **kw):
    n[0] += 1
    ev.append({"event_id": n[0], "ts": T0 + dt, **kw})
for i in range(20):                                    # benign web traffic
    add(i, proto="tcp", src_ip="10.0.0.10", src_port=40000 + i, dst_ip="93.184.216.34", dst_port=443,
        conn_state="SF", tcp_flags="SA", tls_version="TLSv1.3", checksum_valid=True)
for i in range(16):                                    # vertical port scan -> R02 (CRITICAL)
    add(100 + i, proto="tcp", src_ip="198.51.100.7", src_port=50000, dst_ip="10.0.0.20", dst_port=1000 + i, conn_state="REJ")
for i in range(26):                                    # horizontal scan -> R01 (CRITICAL)
    add(200 + i, proto="tcp", src_ip="198.51.100.8", src_port=51000, dst_ip=f"10.0.1.{i + 1}", dst_port=22, conn_state="S0")
add(300, proto="tcp", src_ip="198.51.100.9", dst_ip="10.0.0.20", dst_port=80, tcp_flags="FUP")   # Xmas -> R10 (HIGH)
add(310, log_source="weird", name="fragment_overlap", src_ip="198.51.100.10", dst_ip="10.0.0.20")  # R03 (CRITICAL)
add(320, proto="tcp", src_ip="10.0.0.11", dst_ip="10.0.0.20", dst_port=8080, checksum_valid="bad")   # R32 (LOW)
add(330, proto="tcp", src_ip="10.0.0.12", dst_ip="10.0.0.30", dst_port=443, tls_version="TLSv10")    # S05 (MEDIUM)
add(340, proto="tcp", src_ip="10.0.0.13", dst_ip="203.0.113.66", dst_port=443)                       # blacklist S06 (HIGH)
add(345, proto="tcp", src_ip="2001:db8::bad", dst_ip="2001:db8::1", dst_port=443)                    # blacklist IPv6 S06
for i in range(10):                                    # ICMP sweep -> S02 (MEDIUM)
    add(400 + i, proto="icmp", icmp_type=8, src_ip="198.51.100.20", dst_ip=f"10.0.2.{i + 1}")
add(500, log_source="capture_loss", percent_lost=12.0, acks=500)                                     # R29 (LOW)
add(510, log_source="tunnel", src_ip="10.0.0.40", dst_ip="192.0.2.5")                                # R28 (MEDIUM)
for i in range(3):                                     # repeated FIN_storm from same IP -> 1 alert + 2 suppressed
    add(600 + i * 60, log_source="weird", name="FIN_storm", src_ip="198.51.100.30")
add(700, {"junk": True}) if False else None
ev.append({"ts": "not-a-time", "event_id": 999})       # invalid record: skipped, counted as error
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as fh:
    for e in ev:
        fh.write(json.dumps(e) + "\n")
print(len(ev), "events ->", out)
