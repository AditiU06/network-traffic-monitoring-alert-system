"""Shows one full run through Engine 3, playing the part of E1, E2 and E4.  Run:  python demo.py"""
import json, os, tempfile
from app.engines.e3_data_management import DataManagementService

db = os.path.join(tempfile.mkdtemp(), "demo.db")
e3 = DataManagementService(db)

admin = e3.create_user("System Admin", "admin", "admin@kletech.ac.in", "<password-hash>")   # login data
run_id = e3.new_id()

# --- E1: save the run, then the parsed events (one bad row on purpose) ---
e3.save_processing_run(dict(run_id=run_id, initiated_by=admin, file_name="conn.log", log_type="conn",
                            run_mode="BENCHMARK", started_at="2026-11-14T10:00:00Z"))
events = [dict(event_id=f"e{i}", event_timestamp=1731578400 + i, source_ip="192.168.1.5", source_port=50000 + i,
               destination_ip="10.0.0.9", destination_port=1000 + i, protocol="tcp", conn_state="REJ")
          for i in range(1, 6)]
events.append(dict(event_id="bad1", event_timestamp=1731578410, source_ip="999.1.1.1", destination_ip="10.0.0.9"))
print("E1 insert:", json.dumps(e3.insert_events_batch(run_id, events), indent=1))
e3.save_performance_results(run_id,
    [dict(execution_mode="SEQUENTIAL", worker_count=1, execution_time_sec=12.0, throughput_rec_sec=8000),
     dict(execution_mode="MULTITHREADED", worker_count=8, execution_time_sec=5.0, throughput_rec_sec=19200)],
    dict(speedup_ratio=2.4, equivalence_status="PASS"))
e3.save_processing_run(dict(run_id=run_id, initiated_by=admin, file_name="conn.log", log_type="conn", run_mode="BENCHMARK",
                            started_at="2026-11-14T10:00:00Z", completed_at="2026-11-14T10:00:20Z", status="COMPLETED",
                            input_count=6, valid_count=5, malformed_count=1))

# --- E2: fetch unchecked events, raise one alert, mark events done ---
todo = e3.get_events_for_detection(run_id)
print("\nE2 got", len(todo), "events to check")
print("E2 alert:", e3.save_alerts([dict(alert_id=e3.new_id(), run_id=run_id, severity="HIGH", rule_code="REPEATED_REJECT",
      affected_ip="192.168.1.5", window_start=todo[0]["event_timestamp"], detected_at=todo[-1]["event_timestamp"],
      description="5 rejected connections in 5 seconds", related_event_ids=[e["event_id"] for e in todo])]))
e3.mark_events_evaluated([e["event_id"] for e in todo])

# --- E4: dashboard calls ---
alert = e3.search_alerts(severity="HIGH")["items"][0]
e3.update_alert_status(alert["alert_id"], "ACKNOWLEDGED", admin)
print("\nE4 dashboard:", json.dumps(e3.get_dashboard_summary(), indent=1))
print("E4 speedup:", e3.get_performance_results(run_id)["comparison"])
print("Read speed:", e3.monitor.report())
