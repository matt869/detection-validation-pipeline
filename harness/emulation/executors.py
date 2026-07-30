"""Emulation executors.

Three modes, all producing the same :class:`~harness.core.models.EmulationResult`
so the rest of the pipeline cannot tell them apart:

``dry-run``  Records what *would* run and reserves a plausible time window.
             The default, and the only mode that needs no authorisation.
``replay``   Reserves a real time window on the run's clock without executing
             anything, so the fixture backend can rebase recorded telemetry
             onto it. This is how offline validation gets real latencies.
``local``    Actually runs the command in a subprocess, then runs cleanup.

The interesting property is that ``dry-run`` and ``replay`` still produce a
complete, scoreable run. A team with no lab can still see which rules would be
exercised, which telemetry sources they depend on, and where the gaps are.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import timedelta

from harness.core.logging import get_logger
from harness.core.models import EmulationResult
from harness.core.timeutil import utcnow
from harness.emulation.catalog import EmulationTest
from harness.emulation.safety import SafetyDecision, Target

__all__ = ["DryRunExecutor", "Executor", "LocalExecutor", "ReplayExecutor"]

log = get_logger("emulation")

#: Command templates per executor. Every one is non-interactive, and none uses
#: a shell string that the harness itself interpolates user data into.
_SHELLS: dict[str, Sequence[str]] = {
    "powershell": ("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"),
    "cmd": ("cmd", "/d", "/c"),
    "bash": ("bash", "-c"),
    "sh": ("sh", "-c"),
    "python": ("python", "-c"),
}


class Executor(ABC):
    """Runs (or declines to run) one emulation test."""

    mode: str = "abstract"

    @abstractmethod
    def run(self, test: EmulationTest, target: Target, decision: SafetyDecision) -> EmulationResult:
        ...

    def _skeleton(self, test: EmulationTest, target: Target) -> EmulationResult:
        return EmulationResult(
            emulation_id=test.id,
            executed=False,
            mode=self.mode,
            host=target.host,
            started_at=utcnow(),
        )


class DryRunExecutor(Executor):
    """Reserves a window and records intent. Executes nothing, ever."""

    mode = "dry-run"

    def run(self, test: EmulationTest, target: Target, decision: SafetyDecision) -> EmulationResult:
        started = utcnow()
        summary = (
            f"[dry-run] would execute via {test.executor} on {target.host}: "
            f"{_first_line(test.command) or '(operator-run test, no command)'}"
        )
        log.info("dry-run %s (%s)", test.id, test.technique)
        return EmulationResult(
            emulation_id=test.id,
            executed=False,
            mode=self.mode,
            host=target.host,
            started_at=started,
            finished_at=started + timedelta(seconds=test.duration_seconds),
            stdout=summary,
            error=None if decision.allowed else decision.reason,
        )


class ReplayExecutor(Executor):
    """Reserves a real window so recorded telemetry can be rebased onto it.

    Nothing runs. The window advances by the test's declared duration, which is
    what gives replayed runs believable per-test timing instead of every event
    landing on the same instant.
    """

    mode = "replay"

    def __init__(self, *, inter_test_delay: float = 0.0) -> None:
        self.inter_test_delay = inter_test_delay

    def run(self, test: EmulationTest, target: Target, decision: SafetyDecision) -> EmulationResult:
        started = utcnow()
        log.info("replay %s (%s)", test.id, test.technique)
        return EmulationResult(
            emulation_id=test.id,
            executed=False,
            mode=self.mode,
            host=target.host,
            started_at=started,
            finished_at=started + timedelta(seconds=test.duration_seconds),
            stdout=f"[replay] window reserved for {test.id}",
        )


class LocalExecutor(Executor):
    """Runs the command on this machine, then runs cleanup.

    Only reachable when :class:`~harness.emulation.safety.SafetyPolicy` has
    already allowed the test. It re-checks the decision anyway, because a
    defence that depends on the caller getting the order right is not a defence.
    """

    mode = "local"

    def __init__(self, *, timeout: float = 120.0, run_cleanup: bool = True) -> None:
        self.timeout = timeout
        self.run_cleanup = run_cleanup

    def run(self, test: EmulationTest, target: Target, decision: SafetyDecision) -> EmulationResult:
        if not decision.allowed:
            # Belt and braces: never execute on a denied decision, even if a
            # caller routed here by mistake.
            result = self._skeleton(test, target)
            result.finished_at = result.started_at
            result.error = f"refused by safety policy: {decision.reason}"
            return result

        argv = _SHELLS.get(test.executor)
        if argv is None:
            result = self._skeleton(test, target)
            result.finished_at = result.started_at
            result.error = f"no shell mapping for executor '{test.executor}'"
            return result

        started = utcnow()
        log.warning(
            "executing %s on %s (safe_mode=%s)", test.id, target.host, test.safe_mode
        )
        completed = _invoke(
            [*argv, test.command],
            timeout=min(self.timeout, test.timeout_seconds),
        )
        finished = utcnow()

        cleanup_done = False
        cleanup_output = ""
        if self.run_cleanup and test.has_cleanup:
            cleanup = _invoke([*argv, test.cleanup], timeout=self.timeout)
            cleanup_done = cleanup.returncode == 0
            cleanup_output = cleanup.stderr.strip()
            if not cleanup_done:
                log.error("cleanup failed for %s: %s", test.id, cleanup_output or "no output")

        error: str | None = None
        if completed.returncode is None:
            error = f"timed out after {test.timeout_seconds:.0f}s"
        elif completed.returncode != 0:
            # A non-zero exit is normal for some techniques (the OS blocked it),
            # so it is recorded but does not by itself fail the case - the
            # detection outcome is what matters.
            error = None

        return EmulationResult(
            emulation_id=test.id,
            executed=True,
            mode=self.mode,
            host=target.host,
            started_at=started,
            finished_at=finished,
            exit_code=completed.returncode,
            stdout=_truncate(completed.stdout),
            stderr=_truncate("\n".join(filter(None, [completed.stderr, cleanup_output]))),
            cleanup_performed=cleanup_done,
            error=error,
        )


class _Completed:
    __slots__ = ("returncode", "stderr", "stdout")

    def __init__(self, returncode: int | None, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _invoke(argv: Sequence[str], *, timeout: float) -> _Completed:
    """Run a command with no shell, a hard timeout, and a scrubbed environment."""
    environment = {
        key: value
        for key, value in os.environ.items()
        # Do not leak SIEM credentials into an emulated process.
        if not any(secret in key.upper() for secret in ("TOKEN", "SECRET", "PASSWORD", "KEY"))
    }
    environment["DVP_EMULATION"] = "1"

    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=environment,
            check=False,
        )
        return _Completed(completed.returncode, completed.stdout or "", completed.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return _Completed(None, exc.stdout or "", f"timed out after {timeout:.0f}s")
    except FileNotFoundError as exc:
        return _Completed(127, "", f"interpreter not found: {exc}")
    except OSError as exc:
        return _Completed(126, "", f"could not start process: {exc}")


def _truncate(text: str, limit: int = 4000) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more characters truncated]"


def _first_line(command: str) -> str:
    line = (command or "").strip().splitlines()[0] if command.strip() else ""
    return shlex.quote(line) if " " not in line else line


def build_executor(mode: str, *, timeout: float = 120.0) -> Executor:
    """Factory used by the runner."""
    if mode == "local":
        return LocalExecutor(timeout=timeout)
    if mode == "replay":
        return ReplayExecutor()
    return DryRunExecutor()
