"""Adversary emulation with a default-deny safety policy.

Nothing in this package executes a command unless an operator has recorded an
authorisation reference in configuration *and* passed ``--execute`` on the
command line. Without both, the pipeline plans and reports but does not act.
See ``docs/threat-model.md``.
"""

from __future__ import annotations

from harness.emulation.catalog import EXECUTORS, EmulationTest, TestCatalog
from harness.emulation.executors import (
    DryRunExecutor,
    Executor,
    LocalExecutor,
    ReplayExecutor,
    build_executor,
)
from harness.emulation.runner import EmulationOutcome, EmulationRunner, baseline_anchor
from harness.emulation.safety import SafetyDecision, SafetyPolicy, Target

__all__ = [
    "EXECUTORS",
    "DryRunExecutor",
    "EmulationOutcome",
    "EmulationRunner",
    "EmulationTest",
    "Executor",
    "LocalExecutor",
    "ReplayExecutor",
    "SafetyDecision",
    "SafetyPolicy",
    "Target",
    "TestCatalog",
    "baseline_anchor",
    "build_executor",
]
