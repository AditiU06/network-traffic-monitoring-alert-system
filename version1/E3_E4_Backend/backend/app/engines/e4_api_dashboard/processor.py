"""How E4 hands a run to E1.

E1 (Aditi's engine) will implement `start(...)`. Until it exists, `DemoProcessor` is a simple
stand-in that reads a Zeek conn.log and saves the events through E3, so the API and dashboard
can be tested end to end. It does NO detection and NO real parallel benchmarking.
"""
import logging
import threading
import time
from pathlib import Path


log = logging.getLogger("e4.processor")


class Processor:
    """What E4 expects from E1."""
    def start(self, run_id: str, log_path: Path, mode: str, threads: int) -> None:
        raise NotImplementedError


def _val(x, cast):
    return None if x is None or x in ("-", "(empty)", "") else cast(x)


class DemoProcessor(Processor):
    def __init__(self, service):
        self.service = service

    def start(self, run_id, log_path, mode, threads):
        threading.Thread(target=self._work, args=(run_id, log_path, mode, threads), daemon=True).start()

    def _work(self, run_id, log_path, mode, threads):
        svc, t0 = self.service, time.perf_counter()
        run = svc.get_run(run_id)
        run_args = {k: run[k] for k in ("run_id", "initiated_by", "file_name", "log_type", "run_mode", "started_at")}
        fields, batch, errors, valid, bad = [], [], [], 0, 0
        try:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f, 1):
                    line = line.rstrip("\n")
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    elif line.startswith("#") or not line:
                        continue
                    else:
                        parts = line.split("\t")
                        try:
                            if len(parts) != len(fields):
                                raise ValueError("wrong number of fields")
                            r = dict(zip(fields, parts))
                            batch.append(dict(
                                event_id=f"{run_id}-{n}", event_timestamp=float(r["ts"]),
                                source_ip=r["id.orig_h"], source_port=_val(r.get("id.orig_p"), int),
                                destination_ip=r["id.resp_h"], destination_port=_val(r.get("id.resp_p"), int),
                                protocol=_val(r.get("proto"), str), service=_val(r.get("service"), str),
                                duration=_val(r.get("duration"), float), orig_bytes=_val(r.get("orig_bytes"), int),
                                resp_bytes=_val(r.get("resp_bytes"), int), conn_state=_val(r.get("conn_state"), str),
                                orig_pkts=_val(r.get("orig_pkts"), int), resp_pkts=_val(r.get("resp_pkts"), int)))
                            valid += 1
                        except (ValueError, KeyError) as ex:
                            bad += 1
                            errors.append(dict(line_number=n, error_type="MALFORMED_ROW", error_message=str(ex)))
                    if len(batch) >= 1000:
                        svc.insert_events_batch(run_id, batch); batch = []
            if batch:
                svc.insert_events_batch(run_id, batch)
            if errors:
                svc.save_parse_errors(run_id, errors[:1000])
            secs = max(time.perf_counter() - t0, 1e-9)
            svc.save_performance_results(run_id, [dict(
                execution_mode="MULTITHREADED" if mode == "MULTITHREADED" else "SEQUENTIAL",
                worker_count=threads if mode == "MULTITHREADED" else 1, execution_time_sec=secs,
                throughput_rec_sec=valid / secs)])
            svc.save_processing_run({**run_args, "status": "COMPLETED", "input_count": valid + bad, "valid_count": valid,
                                     "malformed_count": bad, "completed_at": time.time()})
        except Exception:
            log.exception("run %s failed", run_id)      # details stay in the server log
            svc.save_processing_run({**run_args, "status": "FAILED"})
