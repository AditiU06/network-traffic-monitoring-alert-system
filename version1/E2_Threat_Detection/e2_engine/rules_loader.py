"""Loads and validates rules.json and the blacklist file."""
import json
import ipaddress
from typing import List, Set, Tuple

from .models import Rule, Severity

_VALID_TYPES = {"label", "log_source", "match", "blacklist", "window_unique", "window_combo"}


def load_rules(path: str, include_supplementary: bool = True) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    rules, seen = [], set()
    for r in data["rules"]:
        rid = r["rule_id"]
        if rid in seen:
            raise ValueError(f"duplicate rule_id {rid}")
        seen.add(rid)
        sev = Severity.parse(r["severity"])
        if not r.get("detectors"):
            raise ValueError(f"rule {rid} has no detectors (every rule needs a machine-readable condition)")
        for d in r["detectors"]:
            if d.get("type") not in _VALID_TYPES:
                raise ValueError(f"rule {rid}: bad detector type {d.get('type')!r}")
            if d["type"] in ("window_unique", "window_combo") and not d.get("window_sec"):
                raise ValueError(f"rule {rid}: window detector needs window_sec")
        rule = Rule(rule_id=rid, name=r["name"], severity=sev,
                    priority=int(r.get("priority", int(sev))), origin=r["origin"],
                    log_source=r.get("log_source", ""), trigger_text=r.get("trigger_text", ""),
                    indicates=r.get("indicates", ""), detectors=r["detectors"],
                    cooldown_sec=r.get("cooldown_sec"), enabled=r.get("enabled", True),
                    note=r.get("note", ""))
        if rule.origin == "supplementary" and not include_supplementary:
            rule.enabled = False
        rules.append(rule)
    return rules


def load_blacklist(path: str) -> Tuple[Set[str], List[str]]:
    """One IPv4/IPv6 address per line, '#' starts a comment. Returns (hash set, bad lines)."""
    ips, bad = set(), []
    try:
        fh = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return ips, [f"blacklist file not found: {path}"]
    with fh:
        for n, line in enumerate(fh, 1):
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            try:
                ips.add(ipaddress.ip_address(s).compressed)
            except ValueError:
                bad.append(f"line {n}: invalid IP {s!r}")
    return ips, bad
