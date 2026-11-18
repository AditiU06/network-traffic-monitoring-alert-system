"""Fills a database with demo users, a sample Zeek log and a finished run so the dashboard has something to show.
Usage:  python seed_demo.py [database file]      (DEMO ONLY: the passwords below are public)"""
import random, sys, time
from pathlib import Path
from app.engines.e3_data_management import DataManagementService
from app.engines.e4_api_dashboard.security import hash_password

db = sys.argv[1] if len(sys.argv) > 1 else "network_monitor.db"
svc = DataManagementService(db)
PASSWORD = "Demo@12345"
users = {}
for name, role in [("admin", "System Admin"), ("analyst", "Security Analyst"), ("netops", "NetOps Admin")]:
    if not svc.get_user_by_username(name):
        users[name] = svc.create_user(role, name, f"{name}@example.com", hash_password(PASSWORD), name.title())
admin = svc.get_user_by_username("admin")["user_id"]

# a small Zeek-style conn.log (tab separated), with two broken rows on purpose
random.seed(7)
Path("logs").mkdir(exist_ok=True)
cols = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
        "orig_bytes", "resp_bytes", "conn_state", "orig_pkts", "resp_pkts"]
lines = ["#separator \\x09", "#fields\t" + "\t".join(cols)]
t0 = int(time.time()) - 3600
for i in range(300):
    scan = i % 6 == 0
    src = "192.168.1.5" if scan else f"192.168.1.{random.randint(10, 40)}"
    lines.append("\t".join(map(str, [t0 + i, f"C{i}", src, random.randint(30000, 60000), "10.0.0.9",
                 20 + i % 200 if scan else random.choice([80, 443, 53]), random.choice(["tcp", "udp"]), "-",
                 "-" if scan else round(random.random() * 3, 3), "-" if scan else random.randint(100, 9000),
                 "-" if scan else random.randint(100, 90000), "REJ" if scan else "SF", random.randint(1, 20), random.randint(0, 20)])))
lines.insert(50, "garbage row with too few fields")
lines.insert(120, "x\ty")
Path("logs/sample_conn.log").write_text("\n".join(lines) + "\n")

# a finished demo run with alerts and benchmark numbers
if not svc.list_runs()["total"]:
    rid = svc.new_id()
    svc.save_processing_run(dict(run_id=rid, initiated_by=admin, file_name="demo_conn.log", log_type="conn", run_mode="BENCHMARK",
                                 started_at=t0 + 400))
    svc.insert_events_batch(rid, [dict(event_id=f"d{i}", event_timestamp=t0 + 400 + i, source_ip="192.168.1.5", source_port=40000 + i,
                                       destination_ip="10.0.0.9", destination_port=20 + i, protocol="tcp", conn_state="REJ") for i in range(40)]
                            + [dict(event_id=f"n{i}", event_timestamp=t0 + 400 + i, source_ip=f"192.168.1.{10 + i % 5}", source_port=50000 + i,
                                    destination_ip="10.0.0.9", destination_port=443, protocol="tcp", conn_state="SF", orig_bytes=500, resp_bytes=4000,
                                    duration=0.4) for i in range(60)])
    mk = lambda i, sev, rule, ip, desc, ev: dict(alert_id=f"a{i}", run_id=rid, severity=sev, rule_code=rule, affected_ip=ip, window_start=t0 + 400,
                                                 detected_at=t0 + 420 + i, description=desc, related_event_ids=ev)
    svc.save_alerts([mk(1, "HIGH", "PORT_SCAN", "192.168.1.5", "One source contacted 40 different ports in 40 seconds", [f"d{i}" for i in range(40)]),
                     mk(2, "MEDIUM", "REPEATED_REJECT", "192.168.1.5", "40 rejected connections from one source", [f"d{i}" for i in range(10)]),
                     mk(3, "CRITICAL", "BLACKLISTED_IP", "192.168.1.12", "Source is on the IP blacklist", ["n2"]),
                     mk(4, "LOW", "HIGH_DATA_TRANSFER", "192.168.1.11", "Transfer above the configured threshold", ["n1"])])
    svc.save_performance_results(rid, [dict(execution_mode="SEQUENTIAL", worker_count=1, execution_time_sec=12.4, throughput_rec_sec=8064, cpu_usage_pct=96, peak_memory_mb=410),
                                       dict(execution_mode="MULTITHREADED", worker_count=8, execution_time_sec=5.1, throughput_rec_sec=19608, cpu_usage_pct=610, peak_memory_mb=520)],
                                 dict(speedup_ratio=round(12.4 / 5.1, 2), equivalence_status="PASS"))
    svc.save_processing_run(dict(run_id=rid, initiated_by=admin, file_name="demo_conn.log", log_type="conn", run_mode="BENCHMARK", started_at=t0 + 400,
                                 completed_at=t0 + 430, status="COMPLETED", input_count=100, valid_count=100))
print(f"Seeded {db}. Logins (demo only): admin / analyst / netops, password {PASSWORD}")
