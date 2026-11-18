import pytest
from conftest import make_run, ev
from app.engines.e3_data_management import InvalidFilterError, AlertNotFound


@pytest.fixture
def loaded(svc):
    make_run(svc)
    svc.insert_events_batch("r1", [ev(i, ip="10.0.0.1" if i % 2 else "10.0.0.2", ts=f"2026-11-14T10:00:{i:02d}Z") for i in range(1, 21)])
    mk = lambda i, sev, ip: dict(alert_id=f"a{i}", run_id="r1", severity=sev, rule_code=f"R{i}", affected_ip=ip,
                                 window_start="2026-11-14T10:00:00Z", detected_at=f"2026-11-14T10:01:{i:02d}Z", related_event_ids=["e1"])
    svc.save_alerts([mk(1, "LOW", "10.0.0.1"), mk(2, "CRITICAL", "10.0.0.2"), mk(3, "HIGH", "10.0.0.1")])
    return svc


def test_filter_by_ip_and_time_with_paging(loaded):
    r = loaded.search_events(source_ip="10.0.0.1", from_ts="2026-11-14T10:00:05Z", to_ts="2026-11-14T10:00:15Z", size=3)
    assert r["total"] == 6 and len(r["items"]) == 3
    assert r["items"][0]["event_timestamp"] > r["items"][1]["event_timestamp"]  # newest first


def test_empty_filter_is_refused(loaded):
    with pytest.raises(InvalidFilterError):
        loaded.search_events()
    with pytest.raises(InvalidFilterError):
        loaded.search_alerts()


def test_sql_injection_text_is_just_text(loaded):
    assert loaded.search_events(ip="1.1.1.1'; DROP TABLE network_event;--")["total"] == 0
    assert loaded.search_events(run_id="r1")["total"] == 20


def test_alerts_come_back_most_urgent_first(loaded):
    names = [a["severity_name"] for a in loaded.search_alerts(run_id="r1")["items"]]
    assert names == ["CRITICAL", "HIGH", "LOW"]
    assert loaded.search_alerts(severity="high", status="open")["total"] == 1


def test_detection_input_shrinks_as_events_are_marked(loaded):
    first = loaded.get_events_for_detection("r1", limit=5)
    assert len(first) == 5 and first[0]["event_timestamp"] <= first[-1]["event_timestamp"]
    loaded.mark_events_evaluated([e["event_id"] for e in first])
    assert len(loaded.get_events_for_detection("r1", limit=100)) == 15


def test_get_events_for_detection_pagination(loaded):
    # loaded has 20 events for run 'r1'
    page1 = loaded.get_events_for_detection("r1", limit=8, offset=0)
    assert len(page1) == 8
    page2_offset = loaded.get_events_for_detection("r1", limit=8, offset=8)
    assert len(page2_offset) == 8
    assert page1[-1]["event_id"] != page2_offset[0]["event_id"]

    # Keyset cursor pagination
    cursor = (page1[-1]["event_timestamp"], page1[-1]["event_id"])
    page2_cursor = loaded.get_events_for_detection("r1", limit=8, cursor=cursor)
    assert [e["event_id"] for e in page2_cursor] == [e["event_id"] for e in page2_offset]


def test_dashboard_summary(loaded):
    s = loaded.get_dashboard_summary()
    assert s["events_stored"] == 20 and s["alerts_total"] == 3
    assert s["alerts_by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1}
    assert s["alerts_by_status"]["OPEN"] == 3


def test_get_alert_includes_its_events(loaded):
    assert [e["event_id"] for e in loaded.get_alert("a1")["events"]] == ["e1"]
    with pytest.raises(AlertNotFound):
        loaded.get_alert("zzz")
