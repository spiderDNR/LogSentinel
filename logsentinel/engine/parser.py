# logsentinel/engine/parser.py
"""Log parsing utilities for LogSentinel engine.

Tranforms raw log lines into normalized LogEntry objects.
No detection or security logic is performed here.
"""

from datetime import datetime, timezone
from typing import Iterable, List
from .models import LogEntry


def parse_line(raw: str) -> LogEntry:
    """Normalize a single log line into a LogEntry object.

    Args:
        raw (str): Raw log line as read from the log file.
        line_number (int): The line number in the source file (1-based).

    Returns:
        LogEntry: Normalized log entry object.
    """

    cleaned = raw.rstrip("\n")

    return LogEntry(
        timestamp=datetime.now(timezone.utc),
        source="unknown",
        message=cleaned,
        raw=cleaned,
        fields={},
    )


def parse_lines(lines: Iterable[str]) -> List[LogEntry]:
    """
    Parse multiple log lines into normalized LogEntry objects.

    Args:
        lines (Iterable[str]): Iterable of raw log lines.

    Returns:
        List[LogEntry]: Parsed log entries.
    """

    entries: List[LogEntry] = []

    for line in lines:
        entry = parse_line(line)
        entries.append(entry)

    return entries
