"""Data models shared by the checks, the runner, the reports and the GUI."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable, List, Optional

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
MANUAL = "MANUAL"
NA = "N/A"

STATUSES = (FAIL, ERROR, MANUAL, PASS, NA)


@dataclass
class Outcome:
    """What a check function returns."""
    status: str
    message: str = ""
    resources: List[str] = field(default_factory=list)


def passed(message: str = "Compliant") -> Outcome:
    return Outcome(PASS, message)


def failed(message: str, resources: Optional[List[str]] = None) -> Outcome:
    return Outcome(FAIL, message, list(resources or []))


def not_applicable(message: str) -> Outcome:
    return Outcome(NA, message)


def evaluate(total: int, bad: List[str], noun: str) -> Outcome:
    """Standard verdict for 'every <noun> must satisfy X' style checks."""
    if total == 0:
        return not_applicable(f"No {noun} found in this project")
    if bad:
        return failed(f"{len(bad)} of {total} {noun} non-compliant", bad)
    return passed(f"All {total} {noun} compliant")


@dataclass
class Check:
    id: str
    title: str
    section: str
    level: int                      # CIS profile level 1 or 2
    severity: str                   # High / Medium / Low
    description: str
    remediation: str
    func: Optional[Callable] = None  # None => manual check
    scope: str = "project"


@dataclass
class Result:
    check_id: str
    title: str
    section: str
    level: int
    severity: str
    project: str
    status: str
    message: str
    resources: List[str]
    description: str
    remediation: str

    def to_dict(self):
        return asdict(self)
