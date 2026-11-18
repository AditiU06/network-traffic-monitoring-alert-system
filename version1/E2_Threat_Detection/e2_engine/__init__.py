"""E2 - Rule-Based Threat Detection & Alert Prioritization Engine."""
from .config import E2Config
from .engine import E2Engine
from .e3_client import E3Interface, InMemoryE3, EventPage, SaveResult
from .models import Alert, Severity, DetectionSummary

__all__ = ["E2Config", "E2Engine", "E3Interface", "InMemoryE3", "EventPage",
           "SaveResult", "Alert", "Severity", "DetectionSummary"]
