import urllib.request
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def get_field(obj, *keys, default=None):
    if not isinstance(obj, dict):
        return default
    for k in keys:
        if k in obj:
            return obj[k]
    return default

def run_test():
    # 1. Login
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/auth/login",
        data=json.dumps({"username": "admin", "password": "Demo@12345"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read().decode())
    token = data.get("token") or data.get("data", {}).get("token")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print(f"1. Authentication successful. Token: {token[:12]}...")

    # 2. Get Summary
    req_summary = urllib.request.Request(f"{BASE_URL}/api/v1/dashboard/summary", headers=headers)
    summary = json.loads(urllib.request.urlopen(req_summary).read().decode())
    print("\n2. Dashboard Summary:")
    print(f"   Events stored: {get_field(summary, 'eventsStored', 'events_stored')}")
    print(f"   Alerts total: {get_field(summary, 'alertsTotal', 'alerts_total')}")
    print(f"   Alerts by severity: {get_field(summary, 'alertsBySeverity', 'alerts_by_severity')}")

    # 3. List Alerts
    req_alerts = urllib.request.Request(f"{BASE_URL}/api/v1/alerts?status=OPEN", headers=headers)
    alerts = json.loads(urllib.request.urlopen(req_alerts).read().decode())
    items = get_field(alerts, "items", default=[])
    total = get_field(alerts, "total", default=len(items))
    print(f"\n3. Retrieved {total} alerts with status=OPEN:")
    for a in items[:15]:
        rule = str(get_field(a, 'ruleCode', 'rule_code') or '')
        desc = str(get_field(a, 'alertDescription', 'alert_description', 'threatName', 'threat_name') or '')
        if len(desc) > 50:
            desc = desc[:47] + "..."
        sev = str(get_field(a, 'severityName', 'severity_name') or '')
        ip = str(get_field(a, 'affectedIp', 'affected_ip') or '')
        ts = str(get_field(a, 'detectedAt', 'detected_at') or '')
        print(f"   - [{sev:8s}] Rule: {rule:4s} | {desc:50s} | IP: {ip:15s}")

    # 4. Trigger Benchmark Run on sample_conn.log
    print("\n4. Triggering Benchmark run on sample_conn.log...")
    run_payload = {
        "logFile": "sample_conn.log",
        "mode": "BENCHMARK",
        "threads": 4
    }
    req_run = urllib.request.Request(
        f"{BASE_URL}/api/v1/runs",
        data=json.dumps(run_payload).encode(),
        headers=headers
    )
    run_resp = json.loads(urllib.request.urlopen(req_run).read().decode())
    run_id = get_field(run_resp, "runId", "run_id")
    print(f"   Benchmark Run created: ID={run_id}")

    # 5. Poll run status
    print("5. Polling run status until completed...")
    status = "RUNNING"
    for _ in range(40):
        time.sleep(1)
        req_status = urllib.request.Request(f"{BASE_URL}/api/v1/runs/{run_id}", headers=headers)
        status_data = json.loads(urllib.request.urlopen(req_status).read().decode())
        status = get_field(status_data, "status")
        if status in ("COMPLETED", "FAILED"):
            break
    print(f"   Run finished with status: {status}")

    # 6. Check Benchmark Results
    req_bench = urllib.request.Request(f"{BASE_URL}/api/v1/benchmarks?runId={run_id}", headers=headers)
    bench_data = json.loads(urllib.request.urlopen(req_bench).read().decode())
    points = get_field(bench_data, "points", default=[])
    max_speedup = get_field(bench_data, "maxSpeedup", "max_speedup", default=0)
    print(f"\n6. Benchmark Results for run {run_id}:")
    for p in points:
        workers = get_field(p, "workerCount", "worker_count")
        duration = get_field(p, "durationMs", "duration_ms")
        speedup = get_field(p, "speedupFactor", "speedup_factor")
        eps = get_field(p, "eventsPerSec", "events_per_sec")
        print(f"   Workers: {workers} | Duration: {duration} ms | Speedup: {speedup}x | Events/sec: {eps}")
    print(f"   Max Speedup: {max_speedup}x")
    print(f"   NFR-01 Target (>= 1.5x): {'PASSED' if float(max_speedup or 0) >= 1.5 else 'BELOW TARGET'}")

    # 7. Check Alerts for this run
    req_run_alerts = urllib.request.Request(f"{BASE_URL}/api/v1/alerts?runId={run_id}", headers=headers)
    run_alerts = json.loads(urllib.request.urlopen(req_run_alerts).read().decode())
    run_items = get_field(run_alerts, "items", default=[])
    print(f"\n7. Alerts generated in sample_conn.log run: {get_field(run_alerts, 'total')}")
    for a in run_items[:10]:
        rule = str(get_field(a, 'ruleCode', 'rule_code') or '')
        desc = str(get_field(a, 'alertDescription', 'alert_description') or '')
        if len(desc) > 50:
            desc = desc[:47] + "..."
        sev = str(get_field(a, 'severityName', 'severity_name') or '')
        ip = str(get_field(a, 'affectedIp', 'affected_ip') or '')
        print(f"   - [{sev:8s}] Rule: {rule:4s} | {desc:50s} | IP: {ip}")

if __name__ == "__main__":
    run_test()
