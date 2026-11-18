"""Tunable settings for E2. Every value here is a *default* that the team can change.

Values marked CONFIRM are NOT in the Excel sheet or the project documents; they are
configurable defaults proposed by E2 (see README, section "Missing values").
"""
import os
from dataclasses import dataclass, fields

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES_PATH = os.path.join(PACKAGE_DIR, "rules", "rules.json")
DEFAULT_BLACKLIST_PATH = os.path.join(PACKAGE_DIR, "rules", "blacklist.txt")


@dataclass
class E2Config:
    cooldown_sec: float = 300.0          # CONFIRM: docs say "cooldown timer" but give no value
    page_size: int = 5000                # events requested from E3 per call
    send_batch_size: int = 100           # alerts sent to E3 per call
    max_retries: int = 3                 # attempts per alert batch when E3 write fails
    retry_delay_sec: float = 0.5
    max_related_events: int = 100        # cap on related_event_ids in one alert
    prune_every: int = 50000             # expire old window/cooldown state every N events
    require_completed_run: bool = True   # only analyse runs E3 reports as COMPLETED
    include_supplementary_rules: bool = True   # the 6 rules from the docs that are not in the Excel
    max_error_samples: int = 20          # how many error messages to keep in the summary

    @classmethod
    def from_dict(cls, data):
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})
