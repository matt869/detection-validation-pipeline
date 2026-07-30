"""Interpretation of raw query results.

Nothing in this package talks to a backend or runs a command. It takes
observations in and produces verdicts, coverage, deltas, and gate outcomes -
which is what makes all of it directly unit-testable.
"""

from __future__ import annotations

from harness.analysis.baseline import (
    BaselineProfile,
    NoiseFinding,
    ProfileLibrary,
    assess_noise,
    noisy_rules,
)
from harness.analysis.classify import Observation, classify, outcome_rank, redact
from harness.analysis.coverage import (
    AttackReference,
    CoverageReport,
    CoverageTargets,
    TacticCoverage,
    TechniqueCoverage,
    build_coverage,
)
from harness.analysis.diff import CaseDelta, DeltaKind, RunDiff, diff_runs
from harness.analysis.gates import GateOutcome, GateResult, evaluate_gates

__all__ = [
    "AttackReference",
    "BaselineProfile",
    "CaseDelta",
    "CoverageReport",
    "CoverageTargets",
    "DeltaKind",
    "GateOutcome",
    "GateResult",
    "NoiseFinding",
    "Observation",
    "ProfileLibrary",
    "RunDiff",
    "TacticCoverage",
    "TechniqueCoverage",
    "assess_noise",
    "build_coverage",
    "classify",
    "diff_runs",
    "evaluate_gates",
    "noisy_rules",
    "outcome_rank",
    "redact",
]
