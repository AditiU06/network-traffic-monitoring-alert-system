"""Command-line runner.

Demo with a JSONL file (one event per line) and an in-memory stand-in for E3:
    python run_e2.py --events sample_data/sample_events.jsonl --run-id RUN1

Against the real E3 (adapter class you or Soham write, implementing E3Interface):
    python run_e2.py --e3 my_e3_adapter:RealE3 --run-id 42
"""
import argparse
import importlib
import json
import sys

from e2_engine import E2Config, E2Engine, InMemoryE3


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", required=True)
    p.add_argument("--events", help="JSONL file loaded into the in-memory E3 stand-in")
    p.add_argument("--e3", help="module:Class of a real E3Interface implementation")
    p.add_argument("--e3-db", help="Path to SQLite database file to connect via E3ServiceAdapter")
    p.add_argument("--out", help="write the alerts stored in E3 to this JSONL file (demo mode)")
    p.add_argument("--cooldown", type=float, help="override cooldown seconds")
    a = p.parse_args()

    cfg = E2Config()
    if a.cooldown is not None:
        cfg.cooldown_sec = a.cooldown
    if a.e3_db:
        from e2_engine.e3_adapter import E3ServiceAdapter
        e3 = E3ServiceAdapter(a.e3_db)
    elif a.e3:
        mod, cls = a.e3.split(":")
        e3 = getattr(importlib.import_module(mod), cls)()
    elif a.events:
        e3 = InMemoryE3()
        with open(a.events, encoding="utf-8") as fh:
            e3.add_events(a.run_id, [json.loads(l) for l in fh if l.strip()])
    else:
        sys.exit("give --events FILE or --e3 module:Class")

    summary = E2Engine(e3, cfg).run(a.run_id)
    if isinstance(e3, InMemoryE3):
        ranked = sorted(e3.alerts.values(), key=lambda x: (-x["priority"], x["event_time"], x["rule_id"], x["source_ip"] or ""))
        print(f"{'SEVERITY':9} {'RULE':5} {'ALERT TYPE':42} {'SRC':16} {'DST':16} EVENTS")
        for x in ranked:
            print(f"{x['severity']:9} {x['rule_id']:5} {x['alert_type'][:42]:42} {str(x['source_ip']):16} "
                  f"{str(x['destination_ip']):16} {len(x['related_event_ids'])}")
        if a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                for x in ranked:
                    fh.write(json.dumps(x) + "\n")
    print("\nDETECTION SUMMARY")
    print(json.dumps(summary.to_dict(), indent=2))


if __name__ == "__main__":
    main()
