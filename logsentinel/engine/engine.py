# logsentinel/engine/engine.py

"""
LogSentinel Engine

This module provides the core scanning
logic for the LogSentinel security engine.
It coordinates the parsing of log lines,
applies detection rules to log entries,
and aggregates scan results—including threat detections and summaries. The main
interfaces are `scan_lines` for scanning log content from any source and
`scan_file` for direct scanning from filesystem log files.
"""

from pathlib import Path
from typing import Iterable, List

from .parser import parse_lines
from .rules import DEFAULT_RULES
from .models import ScanResult, Threat, LogEntry


# ---------------------------------------------------------------------------
# scan_lines — main pipeline
# ---------------------------------------------------------------------------

def scan_lines(lines: Iterable[str]) -> ScanResult:
    """
    Scan iterable of raw log lines and return aggregated scan result.
    """

    entries: List[LogEntry] = list(parse_lines(lines))
    threats: List[Threat] = []

    for rule in DEFAULT_RULES:
        result = rule.match(entries)

        if result.has_threats:
            threats.extend(result.threats)

    return ScanResult.from_threats(
        threats=threats,
        total_entries=len(entries),
    )


# ---------------------------------------------------------------------------
# scan_file — filesystem wrapper
# ---------------------------------------------------------------------------

def scan_file(path: str | Path) -> ScanResult:
    """
    Scan a log file from disk.
    """

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return scan_lines(f)
