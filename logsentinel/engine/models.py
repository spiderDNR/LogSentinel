"""Data models for the log scanning engine.

This module defines strongly typed data structures used throughout the
log scanning engine, including log entries, threat levels, detections,
and scan results.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List


class ThreatLevel(str, Enum):
    """Enumeration of threat severity levels.

    Threat levels are ordered from least to most severe, providing a
    standardized way to categorize security detections.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    """Represents a single line from a log file.

    Attributes:
        line_number: The line number in the original log file (1-indexed).
        raw: The raw text content of the log line.
    """

    line_number: int
    raw: str


@dataclass
class Detection:
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


@dataclass
class ScanResult:
    """Represents the complete results of a log file scan.

    Attributes:
        total_lines: Total number of lines processed during the scan.
        detections: List of all security threat detections found during
                    the scan, ordered by line number.
    """

    total_lines: int
    detections: List[Detection]
