"""Integration test verifying E2 engine against real E3 DataManagementService."""
import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
