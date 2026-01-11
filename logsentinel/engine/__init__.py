"""
Engine package for LogSentinel.

Contains core detection logic and domain models.
"""

from .models import LogEntry, Threat, ThreatLevel, ScanResult

__all__ = [
    "LogEntry",
    "Threat",
    "ThreatLevel",
    "ScanResult",
]
