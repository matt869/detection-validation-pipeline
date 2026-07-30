"""Markdown report.

Optimised for the place these actually get read: a pull request comment and a
weekly summary email. That means the answer comes first, the failures come
second, and the full case table comes last inside a collapsed block.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from harness.analysis.baseline import NoiseFinding
from harness.analysis.coverage import CoverageReport
from harness.analysis.diff import RunDiff
from harness.analysis.gates import GateOutcome
from harness.core.models import CaseResult, Outcome, RunRecord
from harness.core.timeutil import format_duration, to_iso

__all__ = ["render_markdown"]

_OUTCOME_BADGE = {
    Outcome.DETECTED: "`detected`",
    Outcome.VISIBLE: "`visible`",
    Outcome.BLIND: "`blind`",
    Outcome.ERROR: "`error`",
    Outcome.SKIPPED: "`skipped`",
}


def render_markdown(
    run: RunRecord,
    *,
    coverage: CoverageReport | None = None,
    gates: GateOutcome | None = None,
    diff: RunDiff | None = None,
    noise: Sequence[NoiseFinding] = (),
) -> str:
    summary = run.summarise()
    lines: list[str] = []

    verdict = "PASS" if (gates is None or gates.passed) else "FAIL"
    lines.append(f"# Detection validation - {verdict}")
    lines.append("")
    lines.append(
        f"**{run.profile}** on `{run.backend}` ({run.mode} mode) - "
        f"`{run.run_id}` - {to_iso(run.started_at)}"
    )
    lines.append("")

    # -- headline numbers ---------------------------------------------------
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Cases | {summary.total} |")
    lines.append(
        f"| Detected | {summary.by_outcome.get('detected', 0)} "
        f"({summary.detection_rate:.0%} of scoreable) |"
    )
    lines.append(
        f"| Detection gaps (visible) | {summary.by_outcome.get('visible', 0)} |"
    )
    lines.append(f"| Visibility gaps (blind) | {summary.by_outcome.get('blind', 0)} |")
    if summary.by_outcome.get("error"):
        lines.append(f"| Errored | {summary.by_outcome['error']} |")
    if summary.by_outcome.get("skipped"):
        lines.append(f"| Skipped | {summary.by_outcome['skipped']} |")
    lines.append(f"| Telemetry visibility | {summary.visibility_rate:.0%} |")
    if summary.latency_p50 is not None:
        lines.append(
            f"| Detection latency (p50 / p95) | "
            f"{format_duration(summary.latency_p50)} / "
            f"{format_duration(summary.latency_p95)} |"
        )
    lines.append(f"| Duration | {format_duration(run.duration_seconds)} |")
    lines.append("")

    # -- gates --------------------------------------------------------------
    if gates is not None:
        lines.append("## Gates")
        lines.append("")
        for gate in gates.results:
            if not gate.applicable:
                lines.append(f"- `-` **{gate.name}** - not applicable")
                continue
            mark = "PASS" if gate.passed else "FAIL"
            lines.append(f"- `{mark}` **{gate.name}** - {gate.message}")
            for offender in gate.offenders[:5]:
                lines.append(f"  - {offender}")
            if len(gate.offenders) > 5:
                lines.append(f"  - ...and {len(gate.offenders) - 5} more")
        lines.append("")

    # -- regressions --------------------------------------------------------
    if diff is not None and diff.changed:
        lines.append("## Changes since the previous run")
        lines.append("")
        if diff.baseline_run_id:
            lines.append(f"Compared against `{diff.baseline_run_id}`.")
            lines.append("")
        lines.append("| Change | Rule | Test | Before | After |")
        lines.append("|---|---|---|---|---|")
        for delta in diff.changed[:25]:
            before = delta.before.value if delta.before else "-"
            after = delta.after.value if delta.after else "-"
            lines.append(
                f"| {delta.kind.value} | `{delta.rule_name}` | "
                f"`{delta.emulation_id}` | {before} | {after} |"
            )
        lines.append("")

    # -- the two gap queues -------------------------------------------------
    lines.extend(
        _gap_section(
            "Detection gaps",
            run.gaps("detection"),
            "The telemetry arrived and the rule did not fire. These belong to "
            "detection engineering.",
        )
    )
    lines.extend(
        _gap_section(
            "Visibility gaps",
            run.gaps("visibility"),
            "The telemetry never arrived. Tuning the rule will not help; the log "
            "source needs onboarding. These belong to the platform team.",
        )
    )

    # -- noise --------------------------------------------------------------
    if noise:
        lines.append("## Baseline noise")
        lines.append("")
        lines.append(
            "These rules matched activity in a window where nothing was emulated."
        )
        lines.append("")
        lines.append("| Rule | Hits | Accepted | Severity |")
        lines.append("|---|---|---|---|")
        for finding in noise:
            lines.append(
                f"| `{finding.rule}` | {finding.hits} | {finding.allowance} | "
                f"{finding.severity} |"
            )
        lines.append("")

    # -- coverage -----------------------------------------------------------
    if coverage is not None and coverage.tactics:
        lines.append("## ATT&CK coverage")
        lines.append("")
        lines.append("| Tactic | Detection | Target | Visibility | Target | |")
        lines.append("|---|---:|---:|---:|---:|---|")
        for tactic in sorted(coverage.tactics.values(), key=lambda t: t.order):
            if not tactic.scoreable:
                continue
            mark = "ok" if tactic.meets_target else "below"
            lines.append(
                f"| {tactic.name or tactic.tactic} | {tactic.detection_rate:.0%} | "
                f"{tactic.target_detected:.0%} | {tactic.visibility_rate:.0%} | "
                f"{tactic.target_visible:.0%} | {mark} |"
            )
        lines.append("")

    # -- full case table ----------------------------------------------------
    lines.append("<details>")
    lines.append("<summary>All cases</summary>")
    lines.append("")
    lines.append("| Rule | Technique | Test | Outcome | Status | Latency |")
    lines.append("|---|---|---|---|---|---|")
    for result in sorted(run.results, key=lambda r: (r.outcome.value, r.case.rule_name)):
        techniques = ", ".join(result.case.technique_ids) or "-"
        lines.append(
            f"| `{result.case.rule_name}` | {techniques} | `{result.case.emulation_id}` | "
            f"{_OUTCOME_BADGE.get(result.outcome, result.outcome.value)} | "
            f"{result.status.value} | {format_duration(result.latency_seconds)} |"
        )
    lines.append("")
    lines.append("</details>")
    lines.append("")

    if run.errors:
        lines.append("## Run errors")
        lines.append("")
        lines.extend(f"- {error}" for error in run.errors)
        lines.append("")

    lines.append("---")
    lines.append(
        f"Generated by the detection validation pipeline. "
        f"Operator: `{run.operator}`. "
        f"Rule library: `{run.metadata.get('git_ref') or run.git_ref or 'unknown'}`."
    )
    return "\n".join(lines) + "\n"


def _gap_section(title: str, results: Iterable[CaseResult], preamble: str) -> list[str]:
    results = list(results)
    if not results:
        return []

    lines = [f"## {title} ({len(results)})", "", preamble, ""]
    lines.append("| Rule | Severity | Test | Telemetry | Expected | Note |")
    lines.append("|---|---|---|---|---|---|")
    for result in sorted(
        results, key=lambda r: (-r.case.severity.rank, r.case.rule_name)
    ):
        note = result.notes[0] if result.notes else ""
        if len(note) > 90:
            note = note[:87] + "..."
        expected = result.case.expected.value
        marker = "" if result.status.value == "pass" else " **!**"
        lines.append(
            f"| `{result.case.rule_name}` | {result.case.severity.value} | "
            f"`{result.case.emulation_id}` | {', '.join(result.case.telemetry) or '-'} | "
            f"{expected}{marker} | {note} |"
        )
    lines.append("")
    return lines
