import pytest
from conftest import make_run, ev
from app.engines.e3_data_management import InvalidInput, RunNotFound


def test_batch_inserts_good_rows_and_reports_bad_ones(svc):
    make_run(svc)
    batch = [ev(1), ev(2, source_ip="not-an-ip"), ev(3, source_port=99999), ev(4, conn_state="XYZ"), ev(5), ev(5)]
    r = svc.insert_events_batch("r1", batch)
    assert r["inserted"] == 2 and r["rejected"] == 4 and r["status"] == "PARTIAL"
    reasons = " | ".join(d["reason"] for d in r["rejected_details"])
    assert "valid IPv4/IPv6" in reasons and "out of range" in reasons and "unknown connection state" in reasons and "duplicate" in reasons


def test_retrying_the_same_batch_does_not_duplicate(svc):
    make_run(svc)
    svc.insert_events_batch("r1", [ev(1), ev(2)])
    again = svc.insert_events_batch("r1", [ev(1), ev(2)])
    assert again["inserted"] == 0 and again["rejected"] == 2
    assert svc.search_events(run_id="r1")["total"] == 2


def test_unknown_run_is_refused(svc):
    with pytest.raises(RunNotFound):
        svc.insert_events_batch("nope", [ev(1)])


def test_missing_values_stay_null_and_zeek_epoch_is_accepted(svc):
    make_run(svc)
    svc.insert_events_batch("r1", [ev(1, orig_bytes=None, ts=1731578400.5)])
    row = svc.search_events(run_id="r1")["items"][0]
    assert row["orig_bytes"] is None and row["event_timestamp"].endswith("Z")


def test_new_protocol_is_added_to_lookup(svc):
    make_run(svc)
    svc.insert_events_batch("r1", [ev(1, protocol="GRE")])
    assert svc.search_events(protocol="gre")["total"] == 1


def test_run_counts_must_add_up(svc):
    with pytest.raises(InvalidInput):
        make_run(svc, run_id="bad", input_count=10, valid_count=3, malformed_count=3)


def test_run_can_be_finished_later(svc):
    make_run(svc)
    make_run(svc, status="COMPLETED", completed_at="2026-11-14T10:05:00Z", input_count=3, valid_count=2, malformed_count=1)
    assert svc.get_run("r1")["status"] == "COMPLETED"


def test_metrics_and_comparison(svc):
    make_run(svc)
    svc.save_performance_results("r1",
        [dict(execution_mode="SEQUENTIAL", worker_count=1, execution_time_sec=10.0),
         dict(execution_mode="MULTITHREADED", worker_count=8, execution_time_sec=4.0, throughput_rec_sec=12500)],
        dict(speedup_ratio=2.5, equivalence_status="PASS"))
    res = svc.get_performance_results("r1")
    assert len(res["metrics"]) == 2 and res["comparison"]["speedup_ratio"] == 2.5
    with pytest.raises(InvalidInput):
        svc.save_performance_results("r1", [dict(execution_mode="MULTITHREADED", worker_count=17, execution_time_sec=1.0)])


def test_alerts_link_events_and_repeats_are_suppressed(svc):
    make_run(svc)
    svc.insert_events_batch("r1", [ev(1), ev(2)])
    a = dict(alert_id="a1", run_id="r1", severity="high", rule_code="PORT_SCAN", affected_ip="10.0.0.1",
             window_start="2026-11-14T10:00:00Z", detected_at="2026-11-14T10:00:30Z", related_event_ids=["e1", "e2"])
    assert svc.save_alerts([a])["inserted"] == 1
    again = svc.save_alerts([{**a, "alert_id": "a2"}])
    assert again["inserted"] == 0 and again["suppressed"] == 1
    assert svc.get_alert("a1")["suppression_count"] == 1
    bad = svc.save_alerts([{**a, "alert_id": "a3", "rule_code": "X", "related_event_ids": ["ghost"]},
                           {**a, "alert_id": "a4", "severity": "EXTREME"}])
    assert bad["rejected"] == 2


def test_alert_status_update(svc):
    make_run(svc); svc.insert_events_batch("r1", [ev(1)])
    svc.save_alerts([dict(alert_id="a1", run_id="r1", severity="LOW", rule_code="R", affected_ip="10.0.0.1",
                          window_start="2026-11-14T10:00:00Z", detected_at="2026-11-14T10:00:30Z", related_event_ids=["e1"])])
    svc.update_alert_status("a1", "resolved", svc.user_id)
    a = svc.get_alert("a1")
    assert a["alert_status"] == "RESOLVED" and a["updated_by"] == svc.user_id and a["status_updated_at"]
    with pytest.raises(InvalidInput):
        svc.update_alert_status("a1", "DONE")
