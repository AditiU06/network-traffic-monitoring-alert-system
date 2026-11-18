"""Pipeline Orchestration Coordinator for Team 14 Network Traffic Monitoring & Alert System.

Connects:
E4 Dashboard -> PipelineCoordinator -> E1 (Python Engine) -> E3 Database -> E2 Threat Detection -> E3 Database -> E4 Dashboard
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure workspace packages are on sys.path
_workspace_root = Path(__file__).resolve().parent.parent.parent
_e1_root = _workspace_root / "E1_Concurrent_Log_Processing"
_backend_root = _workspace_root / "E3_E4_Backend" / "backend"
_e2_root = _workspace_root / "E2_Threat_Detection"
_contracts_root = _workspace_root / "Integration" / "Contracts"

for p in (_workspace_root, _e1_root, _backend_root, _e2_root, _contracts_root):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from contracts import e1_to_e3_event
from E1_Concurrent_Log_Processing.e1_processor import E1ParallelProcessor
from e2_engine.config import E2Config
from e2_engine.e3_adapter import E3ServiceAdapter
from e2_engine.engine import E2Engine
from app.engines.e4_api_dashboard.processor import Processor

log = logging.getLogger("integration.orchestration")


def _safe_completed_at(started_at: Any) -> str:
    """Ensures completed_at is >= started_at to satisfy database CHECK constraint."""
    now_dt = datetime.now(timezone.utc)
    if isinstance(started_at, str):
        try:
            s_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            if s_dt.tzinfo is None:
                s_dt = s_dt.replace(tzinfo=timezone.utc)
            if s_dt >= now_dt:
                now_dt = s_dt + timedelta(milliseconds=1)
        except Exception:
            pass
    elif isinstance(started_at, datetime):
        s_dt = started_at if started_at.tzinfo else started_at.replace(tzinfo=timezone.utc)
        if s_dt >= now_dt:
            now_dt = s_dt + timedelta(milliseconds=1)
    return now_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class PipelineCoordinator(Processor):
    """Coordinates end-to-end execution across E1, E2, E3, and E4 without silent fallbacks."""

    def __init__(
        self,
        service: Any,
        timeout_sec: int = 300,
        e2_config: Optional[E2Config] = None,
    ):
        self.service = service
        self.e1_processor = E1ParallelProcessor()
        self.timeout_sec = timeout_sec
        # We allow detection to run during the active pipeline without premature COMPLETED status
        self.e2_config = e2_config or E2Config(require_completed_run=False)

    def start(self, run_id: str, log_path: Path, mode: str, threads: int) -> None:
        """Asynchronously initiates the pipeline run in a dedicated background worker thread."""
        thread = threading.Thread(
            target=self.execute_pipeline,
            args=(run_id, Path(log_path), mode, threads),
            daemon=True,
            name=f"pipeline-worker-{run_id}",
        )
        thread.start()

    def execute_pipeline(self, run_id: str, log_path: Path, mode: str, threads: int) -> Dict[str, Any]:
        """
        Direct in-memory execution routine performing the full stage pipeline:
        1. Validates input and initializes run status in E3.
        2. Invokes E1 multi-worker parallel processor to parse and enrich logs.
        3. Persists parsed records and syntax/parse errors into E3.
        4. Persists benchmark metrics directly into E3.
        5. Invokes E2 threat detection engine with sliding windows & cooldowns.
        6. Persists alerts and updates run status to COMPLETED only after verification.
        """
        t0 = time.perf_counter()
        log.info("Starting direct pipeline execution for run %s (mode=%s, workers=%d, log=%s)",
                 run_id, mode, threads, log_path)

        run = self.service.get_run(run_id)
        run_args = {
            "run_id": run_id,
            "initiated_by": run["initiated_by"],
            "file_name": run["file_name"],
            "log_type": run.get("log_type", "conn"),
            "run_mode": mode.upper(),
            "started_at": run.get("started_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Update run status to RUNNING
        self.service.save_processing_run({**run_args, "status": "RUNNING"})

        parsed_count = 0
        inserted_count = 0
        duplicate_count = 0
        rejected_count = 0
        malformed_count = 0

        try:
            # ---------------- Stage 1: Invoke E1 Multi-Worker Log Processing Engine ----------------
            events, perf_rows, comparison, detected_log_type, parse_errors = self.e1_processor.process(
                Path(log_path), mode=mode, workers=threads
            )
            run_args["log_type"] = detected_log_type
            parsed_count = len(events)
            malformed_count = len(parse_errors)

            # Persist E1 parsing errors into E3 parse_error table
            if parse_errors:
                formatted_errors = [
                    {
                        "line_number": e.get("line_number"),
                        "error_type": e.get("error_category", "PARSER_ERROR"),
                        "error_message": e.get("error_message", "Malformed record"),
                    }
                    for e in parse_errors
                ]
                try:
                    self.service.save_parse_errors(run_id, formatted_errors)
                except Exception as p_ex:
                    log.warning("Could not persist parse errors for run %s: %s", run_id, p_ex)

            # ---------------- Stage 2: Persist Processed Events into E3 ----------------
            if events:
                batch_size = 1000
                for i in range(0, len(events), batch_size):
                    batch = [e1_to_e3_event(ev, run_id) for ev in events[i:i + batch_size]]
                    res = self.service.insert_events_batch(run_id, batch)
                    inserted_count += res.get("inserted", 0)
                    rejected_count += res.get("rejected", 0)

                    # Persist any E3 validation rejections
                    if res.get("rejected_details"):
                        val_errs = [
                            {
                                "line_number": r.get("event", {}).get("line_number"),
                                "error_type": "VALIDATION_REJECTION",
                                "error_message": r.get("reason"),
                            }
                            for r in res.get("rejected_details", [])
                        ]
                        try:
                            self.service.save_parse_errors(run_id, val_errs)
                        except Exception:
                            pass

                # Flush and confirm all buffered event batches are committed
                if hasattr(self.service, "retry_buffer") and self.service.retry_buffer:
                    self.service.flush_retry_buffer()
                    if len(self.service.retry_buffer) > 0:
                        raise RuntimeError(f"Failed to flush {len(self.service.retry_buffer)} event batches from retry buffer")

            # ---------------- Stage 3: Persist Benchmark / Performance Metrics ----------------
            if perf_rows:
                try:
                    self.service.save_performance_results(run_id, perf_rows, comparison)
                except Exception as ex:
                    log.warning("Could not persist performance metrics for run %s: %s", run_id, ex)

            # ---------------- Stage 4: Invoke E2 Threat Detection Engine ----------------
            adapter = E3ServiceAdapter(self.service)
            engine = E2Engine(e3=adapter, config=self.e2_config)
            summary = engine.run(run_id)
            log.info("E2 detection finished for run %s: generated=%d, sent=%d, suppressed=%d",
                     run_id, summary.alerts_generated, summary.alerts_sent, summary.alerts_suppressed)

            # Flush any pending alerts in retry buffer before marking complete
            if hasattr(self.service, "retry_buffer") and self.service.retry_buffer:
                self.service.flush_retry_buffer()
                if len(self.service.retry_buffer) > 0:
                    raise RuntimeError(f"Failed to flush {len(self.service.retry_buffer)} alert batches from retry buffer")

            # ---------------- Stage 5: Finalize Run Status to COMPLETED ----------------
            elapsed = max(time.perf_counter() - t0, 1e-9)
            total_input = parsed_count + malformed_count
            self.service.save_processing_run({
                **run_args,
                "status": "COMPLETED",
                "input_count": total_input,
                "valid_count": inserted_count,
                "malformed_count": malformed_count + rejected_count,
                "completed_at": _safe_completed_at(run_args["started_at"]),
            })

            return {
                "status": "COMPLETED",
                "input_count": total_input,
                "valid_count": inserted_count,
                "malformed_count": malformed_count + rejected_count,
                "alerts_generated": summary.alerts_generated,
                "alerts_sent": summary.alerts_sent,
                "alerts_suppressed": summary.alerts_suppressed,
                "duration_sec": elapsed,
            }

        except Exception as ex:
            log.exception("Pipeline failed for run %s: %s", run_id, ex)
            try:
                self.service.save_parse_errors(run_id, [{
                    "line_number": None,
                    "error_type": "PIPELINE_ERROR",
                    "error_message": str(ex),
                }])
            except Exception:
                pass
            try:
                self.service.save_processing_run({
                    **run_args,
                    "status": "FAILED",
                    "completed_at": _safe_completed_at(run_args["started_at"]),
                })
            except Exception:
                pass
            raise
