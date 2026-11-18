import os, random, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import openpyxl
from e2_engine import E2Config, E2Engine, InMemoryE3, EventPage, SaveResult
from e2_engine.e3_client import E3Interface
from e2_engine.heap import AlertMaxHeap
from e2_engine.models import Alert, Severity
from e2_engine.normalizer import parse_flags, parse_tls, normalize_event, EventValidationError
from e2_engine.config import DEFAULT_RULES_PATH

XLSX = os.path.join(os.path.dirname(DEFAULT_RULES_PATH), "zeek_network_transport_alerts.xlsx")
BL = {"203.0.113.66", "2001:db8::bad"}


def eng(**cfg):
    return E2Engine(config=E2Config(**cfg), blacklist=BL)


def ev(i, ts=1000.0, **kw):
    d = {"event_id": i, "ts": ts}
    d.update(kw)
    return d


def detect(events, **cfg):
    alerts, s = eng(**cfg).process_events(events, "T")
    return alerts, s


def rules_of(alerts):
    return {a.rule_id for a in alerts}


def failed_tcp(i, ts, src, dst, dport):
    return ev(i, ts, proto="tcp", src_ip=src, dst_ip=dst, dst_port=dport, conn_state="REJ")


def scan_ports(n, src="10.0.0.5", dst="10.0.0.9", t0=1000, step=1):
    return [failed_tcp(i, t0 + i * step, src, dst, 1000 + i) for i in range(n)]


def scan_hosts(n, src="10.0.0.5", port=22, t0=1000, step=1):
    return [failed_tcp(i, t0 + i * step, src, f"10.1.{i // 250}.{i % 250 + 1}", port) for i in range(n)]


# one positive example per Excel rule (rule id -> events)
def positives():
    w = lambda name: [ev(1, weird_name=name, src_ip="10.0.0.5", dst_ip="10.0.0.9")]
    P = {
        "R01": scan_hosts(26), "R02": scan_ports(15),
        "R03": w("fragment_overlap"), "R04": w("fragment_inconsistency"),
        "R05": w("fragment_size_inconsistency"), "R06": w("fragment_protocol_inconsistency"),
        "R07": [ev(1, notice_type="Conn::Retransmission_Inconsistency", src_ip="10.0.0.5")],
        "R08": w("FIN_storm"), "R09": w("SYN_after_partial"),
        "R10": [ev(1, proto="tcp", tcp_flags="FUP", src_ip="10.0.0.5")],
        "R11": w("SYN_with_data"), "R12": w("RST_storm"),
        "R13": [ev(1, notice_type="Conn::Content_Gap", src_ip="10.0.0.5")],
        "R14": [ev(1, 1000, src_ip="10.0.0.5", dst_ip="8.8.8.8", ttl=1, proto="udp")] +
               [ev(2 + i, 1001 + i, proto="icmp", icmp_type=11, src_ip=f"10.9.9.{i+1}", dst_ip="10.0.0.5") for i in range(3)],
        "R26": [ev(1, notice_type="ProtocolDetector::Protocol_Found", src_ip="10.0.0.5")],
        "R27": [ev(1, notice_type="DPD::Server_Found", src_ip="10.0.0.5")],
        "R28": [ev(1, log_source="tunnel", src_ip="10.0.0.5")],
        "R29": [ev(1, log_source="capture_loss", percent_lost=12.5)],
        "R30": [ev(1, log_source="capture_loss", acks=0, percent_lost=0)],
        "R31": [ev(1, ip_checksum_valid="bad", src_ip="10.0.0.5")],
        "R32": [ev(1, proto="tcp", checksum_valid=False, src_ip="10.0.0.5")],
        "R33": [ev(1, proto="udp", checksum_valid="invalid", src_ip="10.0.0.5")],
        "R34": [ev(1, proto="icmp", checksum_valid=False, src_ip="10.0.0.5")],
        "R35": w("possible_split_routing"), "R36": w("above_hole_data_without_any_acks"),
        "R37": w("excessive_data_without_further_acks"),
        "R38": [ev(1, log_source="known_hosts.log", src_ip="10.0.0.77")],
    }
    for n, name in {15: "connection_originator_SYN_ack", 16: "repeated_SYN_with_ack", 17: "repeated_SYN_reply_wo_ack",
                    18: "active_connection_reuse", 19: "premature_connection_reuse", 20: "data_before_established",
                    21: "inappropriate_FIN", 22: "window_recision", 23: "SYN_seq_jump", 24: "fragment_with_DF",
                    25: "truncated_IP"}.items():
        P[f"R{n:02d}"] = w(name)
    return P


class TestRulesVsExcel(unittest.TestCase):
    def test_every_excel_row_has_a_rule_with_same_severity(self):
        ws = openpyxl.load_workbook(XLSX, read_only=True)["Alerts"]
        rows = [r for r in ws.iter_rows(min_row=2, values_only=True) if r[0] is not None]
        rules = {r.rule_id: r for r in eng().rules}
        self.assertEqual(len(rows), 38)
        for no, prio, name, *_ in rows:
            r = rules[f"R{int(no):02d}"]
            self.assertEqual(r.name, name)
            self.assertEqual(r.severity.name, prio.upper())
            self.assertEqual(r.priority, int(Severity.parse(prio)))

    def test_every_excel_rule_has_a_positive_detection_test(self):
        P = positives()
        for r in eng().rules:
            if r.origin == "excel":
                self.assertIn(r.rule_id, P, f"no positive test for {r.rule_id}")

    def test_positive_each_excel_rule_fires_with_right_severity(self):
        for rid, events in positives().items():
            with self.subTest(rule=rid):
                alerts, _ = detect(events)
                mine = [a for a in alerts if a.rule_id == rid]
                self.assertTrue(mine, f"{rid} did not fire; got {rules_of(alerts)}")
                rule = next(r for r in eng().rules if r.rule_id == rid)
                self.assertEqual(mine[0].severity, rule.severity.name)


class TestSupplementary(unittest.TestCase):
    def test_syn_flood_boundary(self):
        mk = lambda n: [ev(i, 1000 + i * 0.05, proto="tcp", tcp_flags="S", src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80) for i in range(n)]
        self.assertIn("S01", rules_of(detect(mk(100))[0]))
        self.assertNotIn("S01", rules_of(detect(mk(99))[0]))

    def test_syn_flood_via_conn_state_s0(self):
        evs = [ev(i, 1000 + i * 0.05, proto="tcp", conn_state="S0", src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80) for i in range(100)]
        self.assertIn("S01", rules_of(detect(evs)[0]))

    def test_icmp_sweep_and_flood(self):
        sweep = [ev(i, 1000 + i, proto="icmp", icmp_type=8, src_ip="1.2.3.4", dst_ip=f"10.0.0.{i+1}") for i in range(10)]
        self.assertIn("S02", rules_of(detect(sweep)[0]))
        self.assertNotIn("S02", rules_of(detect(sweep[:9])[0]))
        flood = [ev(i, 1000 + i * 0.05, proto="icmp", icmp_type=8, src_ip="1.2.3.4", dst_ip="10.0.0.1") for i in range(100)]
        self.assertIn("S03", rules_of(detect(flood)[0]))

    def test_abnormal_flags(self):
        for flags in ("NONE", "SF", "SR", 0):
            with self.subTest(flags=flags):
                self.assertIn("S04", rules_of(detect([ev(1, proto="tcp", tcp_flags=flags, src_ip="1.1.1.1")])[0]))
        for flags in ("S", "SA", "FA"):
            self.assertNotIn("S04", rules_of(detect([ev(1, proto="tcp", tcp_flags=flags, src_ip="1.1.1.1")])[0]))

    def test_tls(self):
        for v in ("SSLv3", "TLSv10", "TLSv1.1", "TLS 1.0"):
            self.assertIn("S05", rules_of(detect([ev(1, tls_version=v, src_ip="1.1.1.1")])[0]), v)
        for v in ("TLSv12", "TLSv1.3"):
            self.assertNotIn("S05", rules_of(detect([ev(1, tls_version=v, src_ip="1.1.1.1")])[0]), v)

    def test_blacklist_ipv4_ipv6_either_side(self):
        self.assertIn("S06", rules_of(detect([ev(1, src_ip="203.0.113.66", dst_ip="10.0.0.1")])[0]))
        self.assertIn("S06", rules_of(detect([ev(1, src_ip="10.0.0.1", dst_ip="203.0.113.66")])[0]))
        self.assertIn("S06", rules_of(detect([ev(1, src_ip="2001:DB8:0:0:0:0:0:BAD", dst_ip="10.0.0.1")])[0]))
        self.assertNotIn("S06", rules_of(detect([ev(1, src_ip="10.0.0.1", dst_ip="10.0.0.2")])[0]))

    def test_supplementary_can_be_disabled(self):
        a, _ = detect([ev(1, src_ip="203.0.113.66")], include_supplementary_rules=False)
        self.assertEqual(a, [])

    def test_high_volume_dos_anomaly(self):
        # Trigger S07 with high bytes and 0 resp_bytes
        a, _ = detect([ev(1, proto="tcp", src_ip="192.168.1.50", dst_ip="10.0.0.1", orig_bytes=60000, resp_bytes=0)])
        self.assertIn("S07", rules_of(a))
        # Trigger S07 with high packets and 0 resp_pkts
        a2, _ = detect([ev(2, proto="udp", src_ip="192.168.1.50", dst_ip="10.0.0.1", orig_pkts=1200, resp_pkts=0)])
        self.assertIn("S07", rules_of(a2))
        # Normal traffic should not trigger
        a3, _ = detect([ev(3, proto="tcp", src_ip="192.168.1.50", dst_ip="10.0.0.1", orig_bytes=60000, resp_bytes=5000)])
        self.assertNotIn("S07", rules_of(a3))

    def test_r07_r13_via_conn_history(self):
        # R07 Retransmission inconsistency via history 'r'
        a_r07, _ = detect([ev(1, proto="tcp", src_ip="192.168.1.50", dst_ip="10.0.0.1", history="ShADdfr")])
        self.assertIn("R07", rules_of(a_r07))
        # R13 Content gap via history 'c'
        a_r13, _ = detect([ev(2, proto="tcp", src_ip="192.168.1.50", dst_ip="10.0.0.1", history="ShADdfc")])
        self.assertIn("R13", rules_of(a_r13))


class TestNegativeAndBoundary(unittest.TestCase):
    def test_address_scan_boundary_gt_25(self):
        self.assertNotIn("R01", rules_of(detect(scan_hosts(25))[0]))
        self.assertIn("R01", rules_of(detect(scan_hosts(26))[0]))

    def test_port_scan_boundary_ge_15(self):
        self.assertNotIn("R02", rules_of(detect(scan_ports(14))[0]))
        self.assertIn("R02", rules_of(detect(scan_ports(15))[0]))

    def test_port_scan_window_boundary(self):
        # 15 ports, first and last exactly 300 s apart -> still inside window
        ok = scan_ports(15, step=300 / 14)
        self.assertIn("R02", rules_of(detect(ok)[0]))
        slow = scan_ports(15, step=300 / 14 + 1)   # spans > 300 s: never 15 inside the window
        self.assertNotIn("R02", rules_of(detect(slow)[0]))

    def test_repeated_same_port_is_not_unique_ports(self):
        evs = [failed_tcp(i, 1000 + i, "10.0.0.5", "10.0.0.9", 80) for i in range(50)]
        self.assertNotIn("R02", rules_of(detect(evs)[0]))

    def test_successful_connections_are_not_scans(self):
        evs = [ev(i, 1000 + i, proto="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=1000 + i, conn_state="SF") for i in range(40)]
        a, _ = detect(evs)
        self.assertEqual(a, [])

    def test_different_sources_do_not_combine(self):
        evs = [failed_tcp(i, 1000 + i, f"10.0.0.{i+1}", "10.0.0.9", 1000 + i) for i in range(30)]
        self.assertNotIn("R02", rules_of(detect(evs)[0]))

    def test_capture_loss_boundary(self):
        self.assertNotIn("R29", rules_of(detect([ev(1, log_source="capture_loss", percent_lost=10.0, acks=5)])[0]))
        self.assertIn("R29", rules_of(detect([ev(1, log_source="capture_loss", percent_lost=10.1, acks=5)])[0]))
        self.assertNotIn("R30", rules_of(detect([ev(1, log_source="capture_loss", percent_lost=0, acks=1)])[0]))

    def test_traceroute_needs_3_icmp_and_low_ttl(self):
        low = ev(1, 1000, src_ip="10.0.0.5", dst_ip="8.8.8.8", ttl=1, proto="udp")
        te = lambda i, t: ev(i, t, proto="icmp", icmp_type=11, src_ip=f"10.9.9.{i}", dst_ip="10.0.0.5")
        self.assertNotIn("R14", rules_of(detect([low, te(2, 1001), te(3, 1002)])[0]))            # only 2
        self.assertIn("R14", rules_of(detect([low, te(2, 1001), te(3, 1002), te(4, 1003)])[0]))  # 3
        self.assertNotIn("R14", rules_of(detect([te(2, 1001), te(3, 1002), te(4, 1003)])[0]))    # no low TTL
        ttl10 = ev(1, 1000, src_ip="10.0.0.5", ttl=10, proto="udp")                             # TTL < 10 is strict
        self.assertNotIn("R14", rules_of(detect([ttl10, te(2, 1001), te(3, 1002), te(4, 1003)])[0]))
        late = [low, te(2, 1001), te(3, 1002), te(4, 1000 + 181)]                                 # 3rd ICMP after 180 s
        self.assertNotIn("R14", rules_of(detect(late)[0]))

    def test_xmas_requires_all_three_flags(self):
        self.assertNotIn("R10", rules_of(detect([ev(1, proto="tcp", tcp_flags="FU", src_ip="1.1.1.1")])[0]))
        self.assertIn("R10", rules_of(detect([ev(1, proto="tcp", tcp_flags="SYN,FIN,URG,PSH", src_ip="1.1.1.1")])[0]))

    def test_checksum_ok_no_alert(self):
        self.assertEqual(detect([ev(1, proto="tcp", checksum_valid=True, src_ip="1.1.1.1")])[0], [])

    def test_benign_record_no_alert(self):
        self.assertEqual(detect([ev(1, proto="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=443,
                                    conn_state="SF", tls_version="TLSv1.3")])[0], [])


class TestInvalidAndOptionalFields(unittest.TestCase):
    def test_invalid_records_skipped_run_continues(self):
        evs = [{"ts": 1}, {"event_id": 2}, ev(3, src_ip="not-an-ip"), ev(4, dst_port=99999), "garbage", None,
               ev(5, log_source="tunnel", src_ip="10.0.0.1")]
        a, s = detect(evs)
        self.assertEqual(s.total_events_received, 7)
        self.assertEqual(s.events_evaluated, 1)
        self.assertEqual(s.errors, 6)
        self.assertEqual(rules_of(a), {"R28"})

    def test_missing_optional_fields_do_not_crash(self):
        a, s = detect([ev(1, log_source="capture_loss", percent_lost=50)])
        al = a[0].to_dict()
        for k in ("source_ip", "destination_ip", "source_port", "destination_port"):
            self.assertIsNone(al[k])
        self.assertEqual(s.errors, 0)

    def test_flag_and_tls_parsers(self):
        self.assertEqual(parse_flags(0x29), frozenset("FPU"))
        self.assertEqual(parse_flags("NONE"), frozenset())
        self.assertIsNone(parse_flags(""))
        self.assertEqual(parse_tls("TLSv13"), "TLSv1.3")
        self.assertEqual(parse_tls("SSLv3"), "SSLv3")

    def test_zeek_style_field_names_and_timestamps(self):
        e = normalize_event({"event_id": 1, "ts": "2026-01-01T00:00:00Z", "id.orig_h": "10.0.0.1", "id.resp_p": "443", "id.orig_p": "-"})
        self.assertEqual((e.src_ip, e.dst_port, e.src_port), ("10.0.0.1", 443, None))


class TestCooldown(unittest.TestCase):
    def ws(self, t):  # one weird event per call time
        return ev(int(t), t, weird_name="FIN_storm", src_ip="10.0.0.5")

    def test_repeat_within_cooldown_suppressed(self):
        a, s = detect([self.ws(1000), self.ws(1100), self.ws(1299)], cooldown_sec=300)
        self.assertEqual((len(a), s.alerts_generated, s.alerts_suppressed), (1, 1, 2))

    def test_exactly_at_cooldown_allowed_again(self):
        a, s = detect([self.ws(1000), self.ws(1300)], cooldown_sec=300)
        self.assertEqual((len(a), s.alerts_suppressed), (2, 0))

    def test_different_ip_or_rule_not_suppressed(self):
        evs = [ev(1, 1000, weird_name="FIN_storm", src_ip="10.0.0.5"), ev(2, 1001, weird_name="FIN_storm", src_ip="10.0.0.6"),
               ev(3, 1002, weird_name="RST_storm", src_ip="10.0.0.5")]
        a, s = detect(evs, cooldown_sec=300)
        self.assertEqual((len(a), s.alerts_suppressed), (3, 0))

    def test_continuing_scan_gives_one_alert_not_hundreds(self):
        a, s = detect(scan_ports(200, step=0.5))
        self.assertEqual(sum(1 for x in a if x.rule_id == "R02"), 1)
        self.assertGreater(s.alerts_suppressed, 100)


class TestHeapAndOrdering(unittest.TestCase):
    def mk(self, i, pri, t=1.0, rid="R01", ip="1.1.1.1"):
        return Alert(f"A{i}", rid, "x", "d", Severity(pri).name, pri, "now", t, ip, None, None, None, [i], "T")

    def test_pops_critical_high_medium_low(self):
        h = AlertMaxHeap()
        for i, p in enumerate([1, 3, 2, 4, 1, 4, 2, 3]):
            h.push(self.mk(i, p))
        self.assertEqual([a.priority for a in h.drain()], [4, 4, 3, 3, 2, 2, 1, 1])

    def test_matches_sorted_for_random_input(self):
        rnd = random.Random(7)
        items = [self.mk(i, rnd.randint(1, 4), rnd.randint(0, 20), f"R{rnd.randint(1, 9):02d}") for i in range(500)]
        h = AlertMaxHeap()
        for x in items:
            h.push(x)
        out = h.drain()
        self.assertEqual([x.alert_id for x in out], [x.alert_id for x in sorted(items, key=lambda a: (-a.priority, a.event_time, a.rule_id, a.source_ip or "", a.alert_id))])

    def test_engine_output_ordered_by_severity(self):
        evs = [ev(1, 1000, weird_name="bad_TCP_checksum", src_ip="1.1.1.1"),      # LOW
               ev(2, 1001, weird_name="truncated_IP", src_ip="1.1.1.2"),          # MEDIUM
               ev(3, 1002, weird_name="FIN_storm", src_ip="1.1.1.3"),             # HIGH
               ev(4, 1003, weird_name="fragment_overlap", src_ip="1.1.1.4")]      # CRITICAL
        a, _ = detect(evs)
        self.assertEqual([x.severity for x in a], ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.assertEqual([x.priority for x in a], [4, 3, 2, 1])


class TestConsistencyAndIdempotency(unittest.TestCase):
    def dataset(self):
        evs = scan_ports(20) + scan_hosts(30, src="10.0.0.6", t0=2000) + positives()["R14"] + \
              [ev(900 + i, 1500 + i, weird_name="FIN_storm", src_ip="9.9.9.9") for i in range(3)]
        # unique ids
        for n, e in enumerate(evs):
            e["event_id"] = n + 1
        return evs

    def fp(self, alerts):
        return [a.fingerprint() for a in alerts]

    def test_input_order_and_chunking_do_not_change_alerts(self):
        base = self.dataset()
        ref = self.fp(detect(base)[0])
        self.assertTrue(ref)
        rnd = random.Random(3)
        for _ in range(5):                      # simulates multithreaded E1 inserting in arbitrary order
            shuf = base[:]
            rnd.shuffle(shuf)
            self.assertEqual(self.fp(detect(shuf)[0]), ref)

    def test_rerun_same_run_creates_no_duplicates_in_e3(self):
        e3 = InMemoryE3()
        e3.add_events("R1", self.dataset())
        e = E2Engine(e3, E2Config(page_size=7), blacklist=BL)
        s1 = e.run("R1")
        s2 = e.run("R1")
        self.assertEqual(s1.alerts_sent, s1.alerts_generated)
        self.assertEqual((s2.alerts_sent, s2.alerts_duplicate_at_e3), (0, s2.alerts_generated))
        self.assertEqual(len(e3.alerts), s1.alerts_generated)

    def test_pagination_gives_same_result_as_single_batch(self):
        d = self.dataset()
        a1 = InMemoryE3(); a1.add_events("R", d)
        a2 = InMemoryE3(); a2.add_events("R", d)
        E2Engine(a1, E2Config(page_size=1), blacklist=BL).run("R")
        E2Engine(a2, E2Config(page_size=10000), blacklist=BL).run("R")
        self.assertEqual(sorted(a1.alerts), sorted(a2.alerts))

    def test_run_not_completed_is_refused(self):
        e3 = InMemoryE3(); e3.add_events("R", [], status="RUNNING")
        with self.assertRaises(RuntimeError):
            E2Engine(e3, blacklist=BL).run("R")

    def test_summary_numbers(self):
        e3 = InMemoryE3(); e3.add_events("R", self.dataset() + [{"bad": 1}])
        s = E2Engine(e3, blacklist=BL).run("R")
        self.assertEqual(s.total_events_received, len(self.dataset()) + 1)
        self.assertEqual(s.events_evaluated, len(self.dataset()))
        self.assertEqual(s.errors, 1)
        self.assertEqual(s.rules_loaded, 45)
        self.assertGreater(s.alerts_generated, 0)
        self.assertEqual(sum(s.alerts_by_severity.values()), s.alerts_generated)
        self.assertIn("S05", s.rules_without_eligible_data)   # no TLS data in this dataset
        self.assertNotIn("R03", s.rules_without_eligible_data) # dataset has weird-type records


class Flaky(InMemoryE3):
    def __init__(self, fail_times):
        super().__init__(); self.fail = fail_times
    def save_alerts(self, alerts):
        if self.fail > 0:
            self.fail -= 1
            raise ConnectionError("E3 down")
        return super().save_alerts(alerts)


class TestE3Failures(unittest.TestCase):
    def test_transient_failure_is_retried(self):
        e3 = Flaky(2); e3.add_events("R", [ev(1, weird_name="FIN_storm", src_ip="1.1.1.1")])
        s = E2Engine(e3, E2Config(retry_delay_sec=0), blacklist=BL, sleep=lambda x: None).run("R")
        self.assertEqual((s.alerts_sent, s.alerts_pending, s.errors), (1, 0, 2))

    def test_permanent_failure_keeps_alerts_queued_then_flushes(self):
        e3 = Flaky(99); e3.add_events("R", [ev(1, weird_name="FIN_storm", src_ip="1.1.1.1")])
        e = E2Engine(e3, E2Config(retry_delay_sec=0), blacklist=BL, sleep=lambda x: None)
        s = e.run("R")
        self.assertEqual((s.alerts_sent, s.alerts_pending), (0, 1))
        e3.fail = 0
        s2 = e.flush_pending()
        self.assertEqual((s2.alerts_sent, s2.alerts_pending), (1, 0))


class TestAlertStructure(unittest.TestCase):
    def test_all_required_fields_present(self):
        a, _ = detect(scan_ports(15))
        d = [x for x in a if x.rule_id == "R02"][0].to_dict()
        for k in ("alert_id", "rule_id", "alert_type", "description", "severity", "priority", "detected_at",
                  "source_ip", "destination_ip", "source_port", "destination_port", "related_event_ids", "run_id"):
            self.assertIn(k, d)
        self.assertEqual((d["severity"], d["priority"], d["run_id"], d["source_ip"], d["destination_ip"]),
                         ("CRITICAL", 4, "T", "10.0.0.5", "10.0.0.9"))
        self.assertEqual(len(d["related_event_ids"]), 15)


if __name__ == "__main__":
    unittest.main()
