"""Integration test verifying E2 engine against real E3 DataManagementService."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure E3 backend package root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent.parent / "E3_E4_Backend" / "backend"
if backend_dir.exists() and str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from e2_engine.config import E2Config
from e2_engine.e3_adapter import E3ServiceAdapter
from e2_engine.engine import E2Engine


class TestE2E3RealServiceIntegration(unittest.TestCase):
    def setUp(self):
        try:
            from app.engines.e3_data_management.service import DataManagementService
        except ImportError:
            self.skipTest("DataManagementService from E3 backend is not in PYTHONPATH")

        self.db_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.db_dir, "test_integration.db")
        self.e3_svc = DataManagementService(self.db_path)
        self.admin_id = self.e3_svc.create_user("System Admin", "admin_user", "admin@kletech.ac.in", "pw")

    def test_end_to_end_detection_and_persistence(self):
        run_id = "RUN_INTEGRATION_001"
        self.e3_svc.save_processing_run({
            "run_id": run_id,
            "initiated_by": self.admin_id,
            "file_name": "conn.log",
            "log_type": "conn",
            "run_mode": "SEQUENTIAL",
            "started_at": "2026-11-14T10:00:00Z",
            "status": "COMPLETED"
        })

        # Insert 30 rejected TCP events to trigger R01 (Address Scan)
        events = []
        for i in range(30):
            events.append({
                "event_id": f"e_{i}",
                "event_timestamp": 1731578400 + i,
                "source_ip": "192.168.1.50",
                "source_port": 50000 + i,
                "destination_ip": f"10.0.1.{i+1}",
                "destination_port": 443,
                "protocol": "tcp",
                "conn_state": "REJ"
            })
        self.e3_svc.insert_events_batch(run_id, events)

        # Run E2 Engine via E3ServiceAdapter
        adapter = E3ServiceAdapter(self.e3_svc)
        engine = E2Engine(e3=adapter)
        summary = engine.run(run_id)

        self.assertEqual(summary.total_events_received, 30)
        self.assertEqual(summary.events_evaluated, 30)
        self.assertEqual(summary.alerts_generated, 1)
        self.assertEqual(summary.alerts_sent, 1)
        self.assertEqual(summary.errors, 0)

        # Verify alert in E3
        alerts_found = self.e3_svc.search_alerts(run_id=run_id)
        self.assertEqual(alerts_found["total"], 1)
        stored_alert = alerts_found["items"][0]
        self.assertEqual(stored_alert["rule_code"], "R01")
        self.assertEqual(stored_alert["severity_name"], "CRITICAL")
        self.assertEqual(stored_alert["affected_ip"], "192.168.1.50")

        # Verify events marked evaluated
        remaining = self.e3_svc.get_events_for_detection(run_id)
        self.assertEqual(len(remaining), 0)

    def test_pagination_and_repeated_processing_over_5000_events(self):
        """Regression test verifying pagination for datasets exceeding 5,000 events."""
        run_id = "RUN_PAGINATION_5500"
        total_events = 5500
        self.e3_svc.save_processing_run({
            "run_id": run_id,
            "initiated_by": self.admin_id,
            "file_name": "large_traffic.log",
            "log_type": "conn",
            "run_mode": "MULTITHREADED",
            "started_at": "2026-11-14T10:00:00Z",
            "status": "COMPLETED"
        })

        # Insert 5,500 benign events in batches of 1,000
        batch_size = 1000
        for b_start in range(0, total_events, batch_size):
            batch = []
            for i in range(b_start, min(b_start + batch_size, total_events)):
                batch.append({
                    "event_id": f"large_ev_{i:06d}",
                    "event_timestamp": 1731500000 + i,
                    "source_ip": f"192.168.1.{10 + (i % 200)}",
                    "source_port": 10000 + (i % 50000),
                    "destination_ip": "10.0.0.1",
                    "destination_port": 80,
                    "protocol": "tcp",
                    "conn_state": "SF"
                })
            res = self.e3_svc.insert_events_batch(run_id, batch)
            self.assertEqual(res["status"], "OK")

        # 1. Verify direct pagination via E3 DataManagementService (offset and cursor)
        p1 = self.e3_svc.get_events_for_detection(run_id, limit=2000, offset=0)
        self.assertEqual(len(p1), 2000)
        p2_offset = self.e3_svc.get_events_for_detection(run_id, limit=2000, offset=2000)
        self.assertEqual(len(p2_offset), 2000)
        self.assertNotEqual(p1[-1]["event_id"], p2_offset[0]["event_id"])

        # Keyset cursor pagination should match offset pagination exactly
        cursor = (p1[-1]["event_timestamp"], p1[-1]["event_id"])
        p2_cursor = self.e3_svc.get_events_for_detection(run_id, limit=2000, cursor=cursor)
        self.assertEqual(len(p2_cursor), 2000)
        self.assertEqual([e["event_id"] for e in p2_offset], [e["event_id"] for e in p2_cursor])

        # 2. Run E2 with page_size=2000 to exercise multi-page retrieval across 5,500 events
        cfg = E2Config(page_size=2000)
        adapter = E3ServiceAdapter(self.e3_svc)
        engine = E2Engine(e3=adapter, config=cfg)
        summary = engine.run(run_id)

        self.assertEqual(summary.total_events_received, total_events)
        self.assertEqual(summary.events_evaluated, total_events)
        self.assertEqual(summary.errors, 0)

        # 3. Confirm all events were marked as evaluated (none remaining)
        remaining = self.e3_svc.get_events_for_detection(run_id)
        self.assertEqual(len(remaining), 0)

        # 4. Verify prevention of repeated event processing on subsequent run
        second_adapter = E3ServiceAdapter(self.e3_svc)
        second_engine = E2Engine(e3=second_adapter, config=cfg)
        second_summary = second_engine.run(run_id)
        self.assertEqual(second_summary.total_events_received, 0)
        self.assertEqual(second_summary.events_evaluated, 0)


if __name__ == "__main__":
    unittest.main()
