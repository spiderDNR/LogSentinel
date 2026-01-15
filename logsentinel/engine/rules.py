# logsentinel/engine/rules.py

"""
Detection rules for LogSentinel engine.

Each rule inspects LogEntry objects and may emit Threat detections.
Rules are designed to be stateless and composable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable, List

from .models import LogEntry, Threat, ThreatLevel


# ---------------------------------------------------------------------------
# Rule result
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RuleResult:
    """Represents the output of a detection rule."""

    threats: List[Threat]

    @property
    def has_threats(self) -> bool:
        """Return True if any threats have been detected by this rule.

        Returns:
            bool: True if the threats list is non-empty, otherwise False.
        """
        return bool(self.threats)


# ---------------------------------------------------------------------------
# Base rule interface
# ---------------------------------------------------------------------------

class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    rule_id: str
    description: str
    default_level: ThreatLevel

    @abstractmethod
    def match(self, entries: Iterable[LogEntry]) -> RuleResult:
        """Inspect log entries and return detected threats."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Concrete rules
# ---------------------------------------------------------------------------

class AuthFailureRule(BaseRule):
    """Detect repeated authentication failures."""

    rule_id = "AUTH_FAIL"
    description = "Repeated authentication failures detected"
    default_level = ThreatLevel.MEDIUM

    def match(self, entries: Iterable[LogEntry]) -> RuleResult:
        threats: List[Threat] = []

        for entry in entries:
            msg = entry.message.lower()

            if "failed password" in msg or "authentication failure" in msg:
                threats.append(
                    Threat(
                        rule_id=self.rule_id,
                        description=self.description,
                        level=self.default_level,
                        log_entry=entry,
                    )
                )

        return RuleResult(threats=threats)


class SudoUsageRule(BaseRule):
    """Detect sudo command executions."""

    rule_id = "SUDO_USAGE"
    description = "Sudo command execution detected"
    default_level = ThreatLevel.LOW

    def match(self, entries: Iterable[LogEntry]) -> RuleResult:
        threats: List[Threat] = []

        for entry in entries:
            if "sudo:" in entry.message.lower():
                threats.append(
                    Threat(
                        rule_id=self.rule_id,
                        description=self.description,
                        level=self.default_level,
                        log_entry=entry,
                    )
                )

        return RuleResult(threats=threats)


class PortScanHintRule(BaseRule):
    """Heuristic detection of possible port scanning activity."""

    rule_id = "PORT_SCAN_HINT"
    description = "Possible port scanning behavior"
    default_level = ThreatLevel.HIGH

    def match(self, entries: Iterable[LogEntry]) -> RuleResult:
        threats: List[Threat] = []

        keywords = ("nmap", "port scan", "scan detected")

        for entry in entries:
            msg = entry.message.lower()

            if any(k in msg for k in keywords):
                threats.append(
                    Threat(
                        rule_id=self.rule_id,
                        description=self.description,
                        level=self.default_level,
                        log_entry=entry,
                    )
                )

        return RuleResult(threats=threats)


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[BaseRule] = [
    AuthFailureRule(),
    SudoUsageRule(),
    PortScanHintRule(),
]
