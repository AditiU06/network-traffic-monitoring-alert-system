"""Comprehensive unit and integration test suite for E1 Concurrent Log Processing Engine."""
import tempfile
import time
import unittest
from pathlib import Path

from E1_Concurrent_Log_Processing.e1_processor import (
    E1ParallelProcessor,
    SUPPORTED_LOG_TYPES,
    parse_zeek_record,
    parse_zeek_separator,
)


class TestE1LogParser(unittest.TestCase):
    def setUp(self):
        self.processor = E1ParallelProcessor(max_workers=4)

    def test_parse_zeek_separator_hex_and_escapes(self):
        """Verifies correct decoding of Zeek #separator directives."""
        self.assertEqual(parse_zeek_separator("\\x09"), "\t")
        self.assertEqual(parse_zeek_separator("\\x20"), " ")
        self.assertEqual(parse_zeek_separator("\\t"), "\t")
        self.assertEqual(parse_zeek_separator(","), ",")

    def test_timestamp_fractional_precision_and_no_fabrication(self):
        """Verifies fractional timestamp precision is preserved and no timestamps are fabricated."""
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
        
        # 1. Valid fractional timestamp
        parts = ["1526763439.123456", "C101", "192.168.1.1", "54321", "10.0.0.1", "80"]
        ev, err = parse_zeek_record(parts, fields, 0, "conn", 1, "\t".join(parts))
        self.assertIsNone(err)
        self.assertIsNotNone(ev)
        self.assertIn("2018-05-19", ev["timestamp"])
        self.assertIn("123456", ev["timestamp"])
        self.assertAlmostEqual(ev["ts_epoch"], 1526763439.123456, places=5)

        # 2. Missing/invalid timestamp -> must record error, NOT fabricate fake timestamp
        bad_parts = ["-", "C102", "192.168.1.1", "54321", "10.0.0.1", "80"]
        ev_bad, err_bad = parse_zeek_record(bad_parts, fields, 1, "conn", 2, "\t".join(bad_parts))
        self.assertIsNone(ev_bad)
        self.assertIsNotNone(err_bad)
        self.assertEqual(err_bad.error_category, "INVALID_TIMESTAMP")

        corrupt_parts = ["not_a_time", "C103", "192.168.1.1", "54321", "10.0.0.1", "80"]
        ev_corrupt, err_corrupt = parse_zeek_record(corrupt_parts, fields, 2, "conn", 3, "\t".join(corrupt_parts))
        self.assertIsNone(ev_corrupt)
        self.assertIsNotNone(err_corrupt)
        self.assertEqual(err_corrupt.error_category, "INVALID_TIMESTAMP")

    def test_ip_validation_no_zero_substitution(self):
        """Verifies valid IPs pass and missing IPs are not replaced with 0.0.0.0."""
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
        
        # Valid IPv4 and IPv6
        parts = ["1526763439.0", "C104", "2001:db8::1", "54321", "10.0.0.1", "80"]
        ev, err = parse_zeek_record(parts, fields, 0, "conn", 1, "\t".join(parts))
        self.assertIsNone(err)
        self.assertEqual(ev["source_ip"], "2001:db8::1")
        self.assertEqual(ev["destination_ip"], "10.0.0.1")

        # Invalid IP -> Parse error
        bad_ip_parts = ["1526763439.0", "C105", "999.999.999.999", "54321", "10.0.0.1", "80"]
        ev_bad, err_bad = parse_zeek_record(bad_ip_parts, fields, 1, "conn", 2, "\t".join(bad_ip_parts))
        self.assertIsNone(ev_bad)
        self.assertEqual(err_bad.error_category, "INVALID_SOURCE_IP")

        # Missing IP -> preserved as None, NOT 0.0.0.0
        missing_ip_parts = ["1526763439.0", "C106", "-", "54321", "-", "80"]
        ev_miss, err_miss = parse_zeek_record(missing_ip_parts, fields, 2, "conn", 3, "\t".join(missing_ip_parts))
        self.assertIsNone(err_miss)
        self.assertIsNone(ev_miss["source_ip"])
        self.assertIsNone(ev_miss["destination_ip"])

    def test_port_validation(self):
        """Verifies port range validation (0-65535)."""
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
        
        # Port out of range
        bad_port_parts = ["1526763439.0", "C107", "10.0.0.1", "70000", "10.0.0.2", "80"]
        ev, err = parse_zeek_record(bad_port_parts, fields, 0, "conn", 1, "\t".join(bad_port_parts))
        self.assertIsNone(ev)
        self.assertEqual(err.error_category, "INVALID_SOURCE_PORT")

    def test_field_count_mismatch(self):
        """Verifies row truncation or overflow is flagged as FIELD_COUNT_MISMATCH."""
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
        parts = ["1526763439.0", "C108", "10.0.0.1"]
        ev, err = parse_zeek_record(parts, fields, 0, "conn", 1, "\t".join(parts))
        self.assertIsNone(ev)
        self.assertEqual(err.error_category, "FIELD_COUNT_MISMATCH")

    def test_supported_log_types_coverage(self):
        """Tests field mapping and anomaly preservation for all 18 supported Zeek log types."""
        self.assertGreaterEqual(len(SUPPORTED_LOG_TYPES), 18)

        # 1. Weird log: name -> weird_name, notice -> notice_flag (boolean, not notice_type!)
        w_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer"]
        w_parts = ["1526763439.0", "W101", "192.168.1.10", "4444", "10.0.0.1", "80", "fragment_overlap", "-", "T", "zeek"]
        ev, err = parse_zeek_record(w_parts, w_fields, 0, "weird", 1, "\t".join(w_parts))
        self.assertIsNone(err)
        self.assertEqual(ev["weird_name"], "fragment_overlap")
        self.assertTrue(ev["notice_flag"])
        self.assertIsNone(ev["notice_type"])  # Notice flag must NOT be converted to notice_type!

        # 2. Notice log: note -> notice_type
        n_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "note", "msg", "sub", "action"]
        n_parts = ["1526763439.0", "N101", "192.168.1.11", "5555", "10.0.0.1", "22", "Scan::Port_Scan", "Port scan seen", "sub-info", "Notice::ACTION_LOG"]
        ev_n, err_n = parse_zeek_record(n_parts, n_fields, 1, "notice", 2, "\t".join(n_parts))
        self.assertIsNone(err_n)
        self.assertEqual(ev_n["notice_type"], "Scan::Port_Scan")
        self.assertEqual(ev_n["action"], "Notice::ACTION_LOG")
        self.assertEqual(ev_n["addl"], "sub-info")

        # 3. Tunnel log: tunnel_type
        t_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "tunnel_type", "action"]
        t_parts = ["1526763439.0", "T101", "192.168.1.12", "6666", "10.0.0.1", "0", "Tunnel::GRE", "Tunnel::DISCOVER"]
        ev_t, err_t = parse_zeek_record(t_parts, t_fields, 2, "tunnel", 3, "\t".join(t_parts))
        self.assertIsNone(err_t)
        self.assertEqual(ev_t["tunnel_type"], "Tunnel::GRE")

        # 4. Capture loss log: percent_lost, acks, gaps
        c_fields = ["ts", "ts_delta", "peer", "gaps", "acks", "percent_lost"]
        c_parts = ["1526763439.0", "0.0", "zeek-worker-1", "12", "150", "12.5"]
        ev_c, err_c = parse_zeek_record(c_parts, c_fields, 3, "capture_loss", 4, "\t".join(c_parts))
        self.assertIsNone(err_c)
        self.assertEqual(ev_c["percent_lost"], 12.5)
        self.assertEqual(ev_c["acks"], 150)
        self.assertEqual(ev_c["gaps"], 12)

        # 5. DNS log: query
        d_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query"]
        d_parts = ["1526763439.0", "D101", "192.168.1.13", "5353", "8.8.8.8", "53", "udp", "malicious.example.com"]
        ev_d, err_d = parse_zeek_record(d_parts, d_fields, 4, "dns", 5, "\t".join(d_parts))
        self.assertIsNone(err_d)
        self.assertEqual(ev_d["query"], "malicious.example.com")
        self.assertEqual(ev_d["protocol"], "udp")

        # 6. HTTP log: method, uri, host, status_code
        h_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "method", "host", "uri", "status_code"]
        h_parts = ["1526763439.0", "H101", "192.168.1.14", "45678", "10.0.0.1", "80", "POST", "example.com", "/login", "200"]
        ev_h, err_h = parse_zeek_record(h_parts, h_fields, 5, "http", 6, "\t".join(h_parts))
        self.assertIsNone(err_h)
        self.assertEqual(ev_h["method"], "POST")
        self.assertEqual(ev_h["host"], "example.com")
        self.assertEqual(ev_h["uri"], "/login")
        self.assertEqual(ev_h["status_code"], 200)

    def test_complete_content_sequential_vs_parallel_equivalence(self):
        """Verifies complete field-by-field output equivalence between sequential and parallel workers."""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as tmp:
            tmp.write("#separator \\x09\n")
            tmp.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n")
            t0 = 1526763400
            for i in range(120):
                tmp.write(f"{t0 + i}.123456\tC_{i:04d}\t192.168.1.{10 + (i % 20)}\t{40000 + i}\t10.0.0.1\t{80 + (i % 5)}\ttcp\thttp\t0.05\t{100 + i}\t{500 + i}\tSF\n")
            tmp_path = Path(tmp.name)

        try:
            # Run sequential
            seq_events, seq_perf, _, _, seq_errs = self.processor.process(tmp_path, mode="SEQUENTIAL")
            # Run parallel with 4 workers
            par_events, par_perf, comp, _, par_errs = self.processor.process(tmp_path, mode="MULTITHREADED", workers=4)

            self.assertEqual(len(seq_errs), 0)
            self.assertEqual(len(par_errs), 0)
            self.assertEqual(len(seq_events), 120)
            self.assertEqual(len(par_events), 120)

            # Complete dictionary content equivalence check
            for se, pe in zip(seq_events, par_events):
                self.assertEqual(se, pe)

            # Check benchmark mode equivalence evaluation
            _, _, bench_comp, _, _ = self.processor.process(tmp_path, mode="BENCHMARK", workers=4)
            self.assertEqual(bench_comp["equivalence_status"], "PASS")
            self.assertEqual(bench_comp["mismatch_count"], 0)
        finally:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
