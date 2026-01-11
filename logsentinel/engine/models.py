"""Data models for the log scanning engine.

This module defines strongly typed data structures used throughout the
log scanning engine, including log entries, threat levels, detections,
and scan results.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Dict, Any
from datetime import datetime


class ThreatLevel(IntEnum):
    """Enumeration of threat severity levels.

    Threat levels are ordered from least to most severe, providing a
    standardized way to categorize security detections."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(slots=True)
class LogEntry:
    """Represents a single line from a log file."""
    timestamp: datetime
    source: str
    message: str
    raw: str
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the log entry to a dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "message": self.message,
            "raw": self.raw,
            "fields": self.fields,
        }


@dataclass(slots=True)
class Threat:
    """Represents a security threat detection in a log entry.

    Attributes:
        rule_id: Unique identifier for the detection rule that triggered
                 this detection.
        description: Human-readable description of the detected threat.
        level: The severity level of the detected threat.
        line_number: The line number in the log file where the threat
                     was detected (1-indexed).
    """
    rule_id: str
    description: str
    level: ThreatLevel
    line_number: int

    def to_dict(self) -> dict:
        """Convert the threat to a dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "level": self.level.name,
            "line_number": self.line_number,
        }


@dataclass(slots=True)
class ScanResult:
    """Represents the complete results of a log file scan.

    Attributes:
        total_lines: Total number of lines processed during the scan.
        detections: List of all security threat detections found during
                    the scan, ordered by line number.
    """
    total_entries: int
    threats: List[Threat]

    @property
    def threat_count(self) -> int:
        """Get the total number of threats found in the scan."""
        return len(self.threats)

    def highest_level(self) -> ThreatLevel:
        """Get the highest severity level of the threats found in the scan."""
        if not self.threats:
            return ThreatLevel.INFO
        return max(t.level for t in self.threats)

    def summary_by_level(self) -> dict:
        """Get a summary of the threats found in the scan by severity level."""
        summary: dict[ThreatLevel, int] = {lvl: 0 for lvl in ThreatLevel}
        for threat in self.threats:
            summary[threat.level] += 1
        return summary

    def to_dict(self) -> dict:
        """Convert the scan result to a dictionary representation."""
        return {
            "total_entries": self.total_entries,
            "threat_count": self.threat_count,
            "highest_level": self.highest_level().name,
            "summary": {
                lvl.name: count for lvl,
                count in self.summary_by_level().items()
            },
            "threats": [t.to_dict() for t in self.threats],
        }
