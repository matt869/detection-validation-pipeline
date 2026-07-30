"""Shared primitives: paths, time, identifiers, configuration, models, logging."""

from __future__ import annotations

from harness.core.errors import (
    BackendError,
    ConfigError,
    DvpError,
    EmulationError,
    RuleError,
    SafetyError,
    StorageError,
)
from harness.core.ids import new_case_id, new_run_id, slugify, stable_hash
from harness.core.models import (
    CaseResult,
    CaseStatus,
    Confidence,
    EmulationResult,
    Event,
    Outcome,
    RunRecord,
    Severity,
    ValidationCase,
)
from harness.core.timeutil import TimeWindow, format_duration, parse_duration, parse_ts, utcnow

__all__ = [
    "BackendError",
    "CaseResult",
    "CaseStatus",
    "Confidence",
    "ConfigError",
    "DvpError",
    "EmulationError",
    "EmulationResult",
    "Event",
    "Outcome",
    "RuleError",
    "RunRecord",
    "SafetyError",
    "Severity",
    "StorageError",
    "TimeWindow",
    "ValidationCase",
    "format_duration",
    "new_case_id",
    "new_run_id",
    "parse_duration",
    "parse_ts",
    "slugify",
    "stable_hash",
    "utcnow",
]
