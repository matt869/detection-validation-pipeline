"""Terminal output.

What an operator sees at the end of ``dvp run``. The ordering is the same as the
written report and for the same reason: the verdict first, then the things that
need doing, then everything else.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import TextIO

from harness.analysis.baseline import NoiseFinding
from harness.analysis.coverage import CoverageReport
from harness.analysis.diff import RunDiff
from harness.analysis.gates import GateOutcome
from harness.core.logging import bold, dim, outcome_colour, paint
from harness.core.models import Outcome, RunRecord
from harness.core.timeutil import format_duration

__all__ = ["print_case_lines", "print_summary"]

# Named here rather than inline: f-string expressions cannot contain backslashes
# on Python 3.11, and these are all escape sequences.
_GREEN = "\033[38;5;41m"
_AMBER = "\033[38;5;214m"
_RED = "\033[1;38;5;203m"
_GREEN_BOLD = "\033[1;38;5;41m"


def print_case_lines(run: RunRecord, stream: TextIO | None = None) -> None:
    """One line per case, printed as results arrive."""
    stream = stream or sys.stdout
    for result in run.results:
        _print_case(result, stream)


def print_case(result, stream: TextIO | None = None) -> None:
    _print_case(result, stream or sys.stdout)


def _print_case(result, stream: TextIO) -> None:
    colour = outcome_colour(result.outcome)
    symbol = paint(f"[{result.outcome.symbol}]", colour, stream=stream)
    label = paint(f"{result.outcome.value:<9}", colour, stream=stream)
    latency = (
        dim(f" {format_duration(result.latency_seconds)}", stream=stream)
        if result.latency_seconds is not None
        else ""
    )
    flag = ""
    if result.status.value == "fail":
        flag = paint("  FAIL", _RED, stream=stream)
    elif result.status.value == "unexpected_pass":
        flag = dim("  (better than expected)", stream=stream)
    elif result.is_noisy:
        flag = paint(f"  noisy({result.baseline_hits})", _AMBER, stream=stream)

    name = f"{result.case.rule_name} / {result.case.emulation_id}"
    print(f"  {symbol} {label} {name}{latency}{flag}", file=stream)


def print_summary(
    run: RunRecord,
    *,
    gates: GateOutcome | None = None,
    coverage: CoverageReport | None = None,
    diff: RunDiff | None = None,
    noise: Sequence[NoiseFinding] = (),
    stream: TextIO | None = None,
    verbose: bool = False,
) -> None:
    stream = stream or sys.stdout
    summary = run.summarise()

    def write(text: str = "") -> None:
        print(text, file=stream)

    write()
    write(bold(f"Run {run.run_id}", stream=stream))
    write(
        dim(
            f"profile={run.profile}  backend={run.backend}  mode={run.mode}  "
            f"took {format_duration(run.duration_seconds)}",
            stream=stream,
        )
    )
    write()

    # -- outcome counts ----------------------------------------------------
    for outcome in (Outcome.DETECTED, Outcome.VISIBLE, Outcome.BLIND, Outcome.ERROR, Outcome.SKIPPED):
        count = summary.by_outcome.get(outcome.value, 0)
        if not count and outcome in (Outcome.ERROR, Outcome.SKIPPED):
            continue
        meaning = {
            Outcome.DETECTED: "the control works",
            Outcome.VISIBLE: "telemetry present, rule silent - detection gap",
            Outcome.BLIND: "no telemetry - visibility gap",
            Outcome.ERROR: "could not be measured",
            Outcome.SKIPPED: "not executed",
        }[outcome]
        bar = _sparkbar(count, summary.total)
        write(
            f"  {paint(outcome.value.ljust(9), outcome_colour(outcome), stream=stream)} "
            f"{str(count).rjust(3)}  {bar}  {dim(meaning, stream=stream)}"
        )

    write()
    write(
        f"  detection rate    {_rate(summary.detection_rate)}"
        f"   telemetry visibility  {_rate(summary.visibility_rate)}"
    )
    if summary.latency_p50 is not None:
        write(
            f"  detect latency    p50 {format_duration(summary.latency_p50)}"
            f"   p95 {format_duration(summary.latency_p95)}"
        )
    if summary.noisy_rules:
        label = paint("noisy rules", _AMBER, stream=stream)
        write(
            f"  {label}       "
            f"{summary.noisy_rules} rule(s) also match quiet-baseline activity"
        )

    # -- what to do next ----------------------------------------------------
    detection_gaps = [r for r in run.gaps("detection") if r.status.value != "pass"]
    visibility_gaps = [r for r in run.gaps("visibility") if r.status.value != "pass"]

    if visibility_gaps:
        write()
        write(bold("Visibility gaps - fix collection first", stream=stream))
        for result in visibility_gaps[:10]:
            sources = ", ".join(result.case.telemetry) or "no telemetry declared"
            write(f"  - {result.case.rule_name}: {dim(sources, stream=stream)}")

    if detection_gaps:
        write()
        write(bold("Detection gaps - the telemetry is there, the rule is not", stream=stream))
        for result in detection_gaps[:10]:
            write(
                f"  - {result.case.rule_name} / {result.case.emulation_id} "
                f"{dim(f'({result.telemetry_hits} events seen)', stream=stream)}"
            )

    if diff is not None and diff.regressions:
        write()
        write(bold("Regressions since the previous run", stream=stream))
        for delta in diff.regressions[:10]:
            write(f"  - {delta.describe()}")

    if noise:
        write()
        write(bold("Baseline noise", stream=stream))
        for finding in noise[:10]:
            write(f"  - {finding.describe()}")

    if coverage is not None and verbose:
        failing = coverage.failing_tactics()
        if failing:
            write()
            write(bold("Tactics below target", stream=stream))
            for tactic in failing:
                write(
                    f"  - {tactic.name or tactic.tactic}: "
                    f"detection {tactic.detection_rate:.0%} (target {tactic.target_detected:.0%}), "
                    f"visibility {tactic.visibility_rate:.0%} (target {tactic.target_visible:.0%})"
                )

    # -- verdict -------------------------------------------------------------
    write()
    if gates is None:
        write(dim("no gates evaluated", stream=stream))
        return

    for gate in gates.results:
        if not gate.applicable:
            continue
        mark = (
            paint("pass", _GREEN, stream=stream)
            if gate.passed
            else paint("FAIL", _RED, stream=stream)
        )
        write(f"  {mark}  {gate.name:<20} {dim(gate.message, stream=stream)}")

    write()
    if gates.passed:
        write(paint("PASS", _GREEN_BOLD, stream=stream) + "  all gates satisfied")
    else:
        failures = gates.failures()
        write(paint("FAIL", _RED, stream=stream) + f"  {len(failures)} gate(s) failed")


def _rate(value: float) -> str:
    return f"{value:>5.0%}"


def _sparkbar(count: int, total: int, width: int = 24) -> str:
    if not total:
        return ""
    filled = round(count / total * width)
    return "#" * filled + dim("." * (width - filled))
