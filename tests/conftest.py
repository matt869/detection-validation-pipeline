"""Shared test fixtures.

The whole suite runs offline against the repository's own content. That is
deliberate: the shipped rules and corpora are the most realistic test data
available, and testing against them means a change that breaks real content
fails the build rather than passing against a toy fixture.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from harness.core.config import Settings, load_settings
from harness.core.models import (
    AttackRef,
    EmulationResult,
    Outcome,
    RunRecord,
    Severity,
    ValidationCase,
)
from harness.core.timeutil import utcnow
from harness.pipeline import Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def settings() -> Settings:
    return load_settings(root=REPO_ROOT)


@pytest.fixture(scope="session")
def workspace(settings: Settings) -> Workspace:
    """The repository's own content, loaded once for the whole session."""
    return Workspace.load(settings=settings)


@pytest.fixture
def tmp_settings(tmp_path: Path, settings: Settings) -> Settings:
    """Settings pointing at a throwaway database, sharing the real content."""
    from dataclasses import replace

    from harness.core.config import StorageSettings

    return replace(
        settings,
        storage=StorageSettings(path=str(tmp_path / "test.sqlite3")),
    )


@pytest.fixture
def tmp_workspace(workspace: Workspace, tmp_settings: Settings) -> Workspace:
    from dataclasses import replace

    return replace(workspace, settings=tmp_settings)


# ------------------------------------------------------------------ builders


def make_case(
    *,
    rule_name: str = "test_rule",
    emulation_id: str = "T1059.001-test",
    expected: Outcome = Outcome.DETECTED,
    severity: Severity = Severity.HIGH,
    technique: str = "T1059.001",
    tactic: str = "execution",
    telemetry: list[str] | None = None,
    max_latency: float = 300.0,
    skip_reason: str | None = None,
) -> ValidationCase:
    return ValidationCase(
        case_id=f"case-{rule_name}-{emulation_id}",
        rule_name=rule_name,
        rule_id="00000000-0000-4000-8000-000000000001",
        rule_title=f"Test rule {rule_name}",
        severity=severity,
        attack=[AttackRef(technique=technique, tactic=tactic)],
        platform="windows",
        emulation_id=emulation_id,
        backend="fixture",
        expected=expected,
        telemetry=telemetry if telemetry is not None else ["sysmon_process_creation"],
        max_latency_seconds=max_latency,
        skip_reason=skip_reason,
    )


def make_emulation(
    *,
    emulation_id: str = "T1059.001-test",
    mode: str = "replay",
    executed: bool = False,
    duration: float = 5.0,
    error: str | None = None,
    exit_code: int | None = 0,
) -> EmulationResult:
    started = utcnow()
    return EmulationResult(
        emulation_id=emulation_id,
        executed=executed,
        mode=mode,
        started_at=started,
        finished_at=started + timedelta(seconds=duration),
        host="wks-lab-001",
        exit_code=exit_code,
        error=error,
    )


def make_run(results, *, run_id: str = "run-test-000001", profile: str = "test") -> RunRecord:
    started = utcnow()
    return RunRecord(
        run_id=run_id,
        profile=profile,
        backend="fixture",
        started_at=started,
        finished_at=started + timedelta(seconds=12),
        mode="replay",
        operator="pytest",
        results=list(results),
    )


@pytest.fixture
def case_factory():
    return make_case


@pytest.fixture
def emulation_factory():
    return make_emulation


@pytest.fixture
def run_factory():
    return make_run
