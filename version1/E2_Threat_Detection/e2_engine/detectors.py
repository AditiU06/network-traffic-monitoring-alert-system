"""Detectors: the code behind each rule's machine-readable condition (rules.json).

Single-event detectors : LabelDetector, SourceDetector, MatchDetector, BlacklistDetector
Time-window detectors  : WindowUniqueDetector (N unique X per key within T seconds)
                         WindowComboDetector  (>= N events per key within T, optionally
                                               several event kinds that must co-occur)
Window rules assume events arrive sorted by (ts, event_id); the engine guarantees it.
Window boundary: an event is inside the window if (now - event_ts) <= window_sec.
"""
from __future__ import annotations

import operator
from collections import deque
from typing import Any, Dict, List, Optional

from .models import Hit, NetEvent, Rule
from .normalizer import parse_flags

CMP = {"gt": operator.gt, "ge": operator.ge}
_ALL_FIELDS = ["src_ip", "dst_ip", "src_port", "dst_port"]


# --------------------------------------------------------------- filter mini-language
def _n(v):
    return v.lower() if isinstance(v, str) else v


def _flagset(x):
    return parse_flags(x) if not isinstance(x, frozenset) else x


_OPS = {
    "eq": lambda v, a: _n(v) == _n(a),
    "ne": lambda v, a: _n(v) != _n(a),
    "in": lambda v, a: _n(v) in {_n(x) for x in a},
    "not_in": lambda v, a: _n(v) not in {_n(x) for x in a},
    "lt": lambda v, a: v < a,
    "le": lambda v, a: v <= a,
    "gt": lambda v, a: v > a,
    "ge": lambda v, a: v >= a,
    "has_all": lambda v, a: _flagset(a) <= v,
    "equals_any": lambda v, a: v in {_flagset(x) for x in a},
    "contains": lambda v, a: str(a).lower() in str(v).lower() if v is not None else False,
    "startswith": lambda v, a: str(v).lower().startswith(str(a).lower()) if v is not None else False,
}


def _cond_ok(val, cond) -> bool:
    if isinstance(cond, dict):
        if val is None:
            return bool(cond.get("or_missing"))
        try:
            return all(_OPS[op](val, arg) for op, arg in cond.items() if op != "or_missing")
        except TypeError:
            return False
    if val is None:
        return False
    if isinstance(cond, list):
        return _OPS["in"](val, cond)
    return _OPS["eq"](val, cond)


def match_filter(e: NetEvent, flt: Dict[str, Any]) -> bool:
    return all(_cond_ok(getattr(e, f, None), c) for f, c in flt.items())


def required_fields(flt: Dict[str, Any]) -> List[str]:
    return [f for f, c in flt.items() if not (isinstance(c, dict) and c.get("or_missing"))]


def proto_hint(flt: Dict[str, Any]):
    c = flt.get("proto")
    if c is None:
        return None
    if isinstance(c, dict):
        c = c.get("eq", c.get("in"))
    if c is None:
        return None
    return {str(x).lower() for x in (c if isinstance(c, list) else [c])}


def _has(e, fields):
    return all(getattr(e, f, None) is not None for f in fields)


def _hit(rule, e, detail, report=None, values=None, related=None):
    report = report or _ALL_FIELDS
    v = values if values is not None else {f: getattr(e, f) for f in report}
    return Hit(rule=rule, detail=detail, src_ip=v.get("src_ip"), dst_ip=v.get("dst_ip"),
               src_port=v.get("src_port"), dst_port=v.get("dst_port"),
               related_event_ids=related or [e.event_id],
               trigger_event_id=e.event_id, event_time=e.ts)


# --------------------------------------------------------------- single-event
class LabelDetector:
    kind = "label"

    def __init__(self, rule, spec):
        self.rule = rule
        self.labels = {l.lower() for l in spec["labels"]}

    def evaluate(self, e):
        hit = None
        if e.labels & self.labels:
            matched = sorted(e.labels & self.labels)[0]
            hit = _hit(self.rule, e, f"event reported as '{matched}'")
        return True, hit


class SourceDetector:
    kind = "source"

    def __init__(self, rule, spec):
        self.rule = rule
        self.sources = {s.lower() for s in spec["sources"]}

    def evaluate(self, e):
        hit = _hit(self.rule, e, f"record from {e.log_source}.log") if e.log_source in self.sources else None
        return True, hit


class MatchDetector:
    kind = "match"

    def __init__(self, rule, spec):
        self.rule = rule
        self.filter = spec["filter"]
        self.required = required_fields(self.filter)
        self.protos = proto_hint(self.filter)

    def evaluate(self, e):
        if not _has(e, self.required):
            return False, None
        if not match_filter(e, self.filter):
            return True, None
        bits = [f"{f}={getattr(e, f) if f != 'tcp_flags' else ''.join(sorted(e.tcp_flags))!r}"
                for f in self.required]
        return True, _hit(self.rule, e, "condition met: " + ", ".join(bits))


class BlacklistDetector:
    kind = "blacklist"
    protos = None

    def __init__(self, rule, spec, blacklist):
        self.rule = rule
        self.blacklist = blacklist       # hash set of normalised IP strings

    def evaluate(self, e):
        if e.src_ip is None and e.dst_ip is None:
            return False, None
        for side in ("src_ip", "dst_ip"):
            ip = getattr(e, side)
            if ip is not None and ip in self.blacklist:
                return True, _hit(self.rule, e, f"blacklisted {side} {ip}")
        return True, None


# --------------------------------------------------------------- window detectors
class _UniqueWindow:
    __slots__ = ("dq", "counts")

    def __init__(self):
        self.dq = deque()
        self.counts: Dict[Any, int] = {}

    def evict(self, ts, window):
        dq = self.dq
        while dq and ts - dq[0][0] > window:
            _, _, v = dq.popleft()
            c = self.counts[v] - 1
            if c:
                self.counts[v] = c
            else:
                del self.counts[v]

    def add(self, ts, eid, v, window):
        self.evict(ts, window)
        self.dq.append((ts, eid, v))
        self.counts[v] = self.counts.get(v, 0) + 1


class WindowUniqueDetector:
    kind = "window_unique"

    def __init__(self, rule, spec, max_related=100):
        self.rule = rule
        self.filter = spec.get("filter", {})
        self.group_by = spec["group_by"]
        self.unique_field = spec["unique_field"]
        self.window = float(spec["window_sec"])
        self.threshold = spec["threshold"]
        self.op = spec["op"]
        self.report = spec.get("report", self.group_by)
        self.required = required_fields(self.filter) + self.group_by + [self.unique_field]
        self.protos = proto_hint(self.filter)
        self.max_related = max_related
        self.groups: Dict[tuple, _UniqueWindow] = {}

    def evaluate(self, e):
        if not _has(e, self.required):
            return False, None
        if not match_filter(e, self.filter):
            return True, None
        key = tuple(getattr(e, f) for f in self.group_by)
        w = self.groups.get(key)
        if w is None:
            w = self.groups[key] = _UniqueWindow()
        w.add(e.ts, e.event_id, getattr(e, self.unique_field), self.window)
        n = len(w.counts)
        if CMP[self.op](n, self.threshold):
            ids = [x[1] for x in w.dq][: self.max_related]
            detail = (f"{n} unique {self.unique_field} values for {dict(zip(self.group_by, key))} "
                      f"within {self.window:g}s (threshold {self.op} {self.threshold})")
            return True, _hit(self.rule, e, detail, report=self.report, related=ids)
        return True, None

    def prune(self, now):
        for k in [k for k, w in self.groups.items() if not w.dq or now - w.dq[-1][0] > self.window]:
            del self.groups[k]


class WindowComboDetector:
    """Each component = (filter, key fields). The rule fires when, for ONE key value,
    every component has >= min_count matching events inside the window.
    One component = a plain 'count >= N in T seconds'. Two = e.g. traceroute."""
    kind = "window_combo"

    def __init__(self, rule, spec, max_related=100):
        self.rule = rule
        self.window = float(spec["window_sec"])
        self.max_related = max_related
        self.report = spec.get("report")
        self.comps = []
        for c in spec["components"]:
            keyf = c["key_fields"]
            self.comps.append({
                "filter": c.get("filter", {}),
                "key_fields": keyf,
                "key_as": c.get("key_as", keyf),
                "min": c["min_count"],
                "required": required_fields(c.get("filter", {})) + keyf,
            })
        protos = [proto_hint(c["filter"]) for c in self.comps]
        self.protos = None if any(p is None for p in protos) else set().union(*protos)
        self.state: Dict[tuple, deque] = {}

    def _evict(self, dq, ts):
        while dq and ts - dq[0][0] > self.window:
            dq.popleft()

    def evaluate(self, e):
        eligible, fired_key = False, None
        for i, c in enumerate(self.comps):
            if not _has(e, c["required"]) or not match_filter(e, c["filter"]):
                if _has(e, c["required"]):
                    eligible = True
                continue
            eligible = True
            key = tuple(getattr(e, f) for f in c["key_fields"])
            dq = self.state.setdefault((i, key), deque())
            self._evict(dq, e.ts)
            dq.append((e.ts, e.event_id))
            fired_key = key
            # evaluate this key across all components
            ok, ids = True, []
            for j, cj in enumerate(self.comps):
                dqj = self.state.get((j, key))
                if dqj is None:
                    ok = False
                    break
                self._evict(dqj, e.ts)
                if len(dqj) < cj["min"]:
                    ok = False
                    break
                ids.extend(x[1] for x in dqj)
            if ok:
                names = self.comps[i]["key_as"]
                values = dict(zip(names, key))
                detail = (f"{'; '.join(str(len(self.state[(j, key)])) + ' event(s) (need ' + str(cj['min']) + ')' for j, cj in enumerate(self.comps))} "
                          f"for key {values} within {self.window:g}s")
                return True, _hit(self.rule, e, detail, values=values, related=ids[: self.max_related])
        return eligible, None

    def prune(self, now):
        for k in [k for k, dq in self.state.items() if not dq or now - dq[-1][0] > self.window]:
            del self.state[k]


# --------------------------------------------------------------- dispatcher
class DetectorSet:
    """Builds every detector from the rules and indexes them in hash maps:
       label -> detectors, log_source -> detectors, proto -> detectors."""

    def __init__(self, rules: List[Rule], blacklist, max_related=100):
        self.label_index: Dict[str, list] = {}
        self.source_index: Dict[str, list] = {}
        self.proto_index: Dict[str, list] = {}
        self.any_proto: list = []
        self.window_detectors: list = []
        self.rules = [r for r in rules if r.enabled]
        self.eligible_counts: Dict[str, int] = {r.rule_id: 0 for r in self.rules}
        self._label_rules, self._source_rules = {}, {}
        self.saw_labels = False
        self.seen_sources = set()
        for rule in self.rules:
            for spec in rule.detectors:
                t = spec["type"]
                if t == "label":
                    d = LabelDetector(rule, spec)
                    for lab in d.labels:
                        self.label_index.setdefault(lab, []).append(d)
                    self._label_rules[rule.rule_id] = True
                    continue
                if t == "log_source":
                    d = SourceDetector(rule, spec)
                    for s in d.sources:
                        self.source_index.setdefault(s, []).append(d)
                    self._source_rules.setdefault(rule.rule_id, set()).update(d.sources)
                    continue
                if t == "match":
                    d = MatchDetector(rule, spec)
                elif t == "blacklist":
                    d = BlacklistDetector(rule, spec, blacklist)
                elif t == "window_unique":
                    d = WindowUniqueDetector(rule, spec, max_related)
                    self.window_detectors.append(d)
                elif t == "window_combo":
                    d = WindowComboDetector(rule, spec, max_related)
                    self.window_detectors.append(d)
                else:
                    raise ValueError(f"rule {rule.rule_id}: unknown detector type {t!r}")
                if d.protos:
                    for p in d.protos:
                        self.proto_index.setdefault(p, []).append(d)
                else:
                    self.any_proto.append(d)

    def evaluate(self, e: NetEvent):
        """Returns (hits, number_of_detector_checks)."""
        cands = []
        if e.labels:
            self.saw_labels = True
            for lab in e.labels:
                cands.extend(self.label_index.get(lab, ()))
        if e.log_source:
            self.seen_sources.add(e.log_source)
            cands.extend(self.source_index.get(e.log_source, ()))
        cands.extend(self.any_proto)
        if e.proto:
            cands.extend(self.proto_index.get(e.proto, ()))
        hits: Dict[str, Hit] = {}
        for d in cands:
            eligible, hit = d.evaluate(e)
            if eligible:
                self.eligible_counts[d.rule.rule_id] += 1
            if hit is not None:
                hits.setdefault(d.rule.rule_id, hit)
        return [hits[k] for k in sorted(hits)], len(cands)

    def prune(self, now):
        for d in self.window_detectors:
            d.prune(now)

    def rules_without_data(self) -> List[str]:
        out = []
        for r in self.rules:
            if self.eligible_counts[r.rule_id] > 0:
                continue
            if r.rule_id in self._label_rules and self.saw_labels:
                continue
            if self._source_rules.get(r.rule_id, set()) & self.seen_sources:
                continue
            out.append(r.rule_id)
        return out
