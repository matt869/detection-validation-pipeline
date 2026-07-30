"""HTML views.

Fragments are built in Python and dropped into ``{{ }}`` placeholders in
``dashboard/templates/``. Same reasoning as the reports: one shape, testable
conditionals, no template engine to install.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from harness.analysis.coverage import build_coverage
from harness.core.models import Outcome, RunRecord
from harness.core.timeutil import format_duration
from harness.reporting.template import escape, render

__all__ = ["render_coverage", "render_error", "render_index", "render_rule", "render_run"]

_TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
_STATIC = Path(__file__).resolve().parents[1] / "static"

_OUTCOME_ORDER = (Outcome.DETECTED, Outcome.VISIBLE, Outcome.BLIND, Outcome.ERROR, Outcome.SKIPPED)
_OUTCOME_LABEL = {
    Outcome.DETECTED: "Detected",
    Outcome.VISIBLE: "Detection gap",
    Outcome.BLIND: "Visibility gap",
    Outcome.ERROR: "Errored",
    Outcome.SKIPPED: "Skipped",
}


def _template(name: str) -> str:
    return (_TEMPLATES / name).read_text(encoding="utf-8")


def _asset(name: str) -> str:
    path = _STATIC / name
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _page(title: str, nav: str, body: str, *, subtitle: str = "") -> str:
    return render(
        _template("layout.html"),
        {
            "title": title,
            "heading": title,
            "subtitle": subtitle,
            "nav": nav,
            "body": body,
            "style": _asset("dashboard.css"),
            "script": _asset("dashboard.js"),
        },
    )


def _nav(active: str, extra: Sequence[tuple[str, str]] = ()) -> str:
    items = [("Runs", "/"), ("Coverage", "/coverage"), ("Rules", "/rules")]
    links = [
        f'<a href="{escape(href)}" class="{"active" if label.lower() == active else ""}">'
        f"{escape(label)}</a>"
        for label, href in items
    ]
    links.extend(f'<a href="{escape(href)}">{escape(label)}</a>' for label, href in extra)
    return "".join(links)


# ------------------------------------------------------------------- index


def render_index(runs: Sequence[Any], latest: RunRecord | None) -> str:
    if not runs:
        body = (
            '<p class="empty">No runs stored yet. Run '
            "<code>dvp run --profile quick-smoke</code> and refresh.</p>"
        )
        return _page("Detection validation", _nav("runs"), body)

    summary_block = ""
    if latest is not None:
        summary = latest.summarise()
        summary_block = (
            f'<div class="tiles">'
            f"{_tile('Latest run', latest.run_id[-6:], latest.profile)}"
            f"{_tile('Detected', str(summary.by_outcome.get('detected', 0)), f'{summary.detection_rate:.0%}', css='detected')}"
            f"{_tile('Detection gaps', str(summary.by_outcome.get('visible', 0)), 'rule silent', css='visible')}"
            f"{_tile('Visibility gaps', str(summary.by_outcome.get('blind', 0)), 'no telemetry', css='blind')}"
            f"{_tile('Visibility', f'{summary.visibility_rate:.0%}', 'of scoreable')}"
            f"</div>"
            f"{_outcome_bar(summary)}"
        )

    rows = "".join(
        "<tr>"
        f'<td><a href="/run/{escape(r.run_id)}"><code>{escape(r.run_id)}</code></a></td>'
        f"<td>{escape(r.profile)}</td>"
        f"<td>{escape(r.backend)}</td>"
        f"<td>{escape(r.mode)}</td>"
        f'<td class="mono">{escape((r.started_at or "")[:19].replace("T", " "))}</td>'
        f'<td class="num">{r.total_cases}</td>'
        f'<td class="num detected">{r.detected}</td>'
        f'<td class="num visible">{r.visible}</td>'
        f'<td class="num blind">{r.blind}</td>'
        f'<td class="num">{r.detection_rate:.0%}</td>'
        f"<td>{_gate_pill(r.gates_passed)}</td>"
        "</tr>"
        for r in runs
    )

    body = (
        f"{summary_block}"
        "<h2>Runs</h2><div class='table-wrap'><table><thead><tr>"
        "<th>Run</th><th>Profile</th><th>Backend</th><th>Mode</th><th>Started</th>"
        '<th class="num">Cases</th><th class="num">Det</th><th class="num">Vis</th>'
        '<th class="num">Blind</th><th class="num">Rate</th><th>Gates</th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )
    return _page("Detection validation", _nav("runs"), body)


# --------------------------------------------------------------------- run


def render_run(run: RunRecord, workspace) -> str:
    summary = run.summarise()
    coverage = build_coverage(run, reference=workspace.attack, targets=workspace.targets)

    tiles = (
        f'<div class="tiles">'
        f"{_tile('Cases', str(summary.total), run.profile)}"
        f"{_tile('Detected', str(summary.by_outcome.get('detected', 0)), f'{summary.detection_rate:.0%}', css='detected')}"
        f"{_tile('Detection gaps', str(summary.by_outcome.get('visible', 0)), 'rule silent', css='visible')}"
        f"{_tile('Visibility gaps', str(summary.by_outcome.get('blind', 0)), 'no telemetry', css='blind')}"
        f"{_tile('Latency p50', format_duration(summary.latency_p50), f'p95 {format_duration(summary.latency_p95)}')}"
        f"</div>"
    )

    rows = []
    for result in sorted(
        run.results,
        key=lambda r: (
            _OUTCOME_ORDER.index(r.outcome) if r.outcome in _OUTCOME_ORDER else 9,
            -r.case.severity.rank,
            r.case.rule_name,
        ),
    ):
        notes = " ".join(result.notes)
        queries = "".join(
            f"<div class='query'><b>{escape(kind)}</b><pre>{escape(text)}</pre></div>"
            for kind, text in result.queries.items()
        )
        evidence = ""
        if result.evidence:
            items = "".join(f"<pre>{escape(_compact(row))}</pre>" for row in result.evidence[:3])
            evidence = f"<div class='evidence'><b>evidence</b>{items}</div>"

        rows.append(
            "<tr class='case-row' data-outcome='" + result.outcome.value + "'>"
            f'<td><a href="/rule/{escape(result.case.rule_name)}">'
            f"<code>{escape(result.case.rule_name)}</code></a></td>"
            f"<td>{escape(', '.join(result.case.technique_ids) or '-')}</td>"
            f"<td><code>{escape(result.case.emulation_id)}</code></td>"
            f'<td><span class="pill {result.outcome.value}">{escape(result.outcome.value)}</span></td>'
            f'<td><span class="pill {result.status.value}">{escape(result.status.value)}</span></td>'
            f'<td class="num">{result.detection_hits}</td>'
            f'<td class="num">{result.telemetry_hits}</td>'
            f'<td class="num">{result.baseline_hits}</td>'
            f'<td class="num">{escape(format_duration(result.latency_seconds))}</td>'
            "</tr>"
            "<tr class='detail'><td colspan='9'>"
            f'<div class="note">{escape(notes)}</div>{queries}{evidence}'
            "</td></tr>"
        )

    filters = (
        '<div class="filters">'
        '<button data-filter="all" class="active">All</button>'
        '<button data-filter="detected">Detected</button>'
        '<button data-filter="visible">Detection gaps</button>'
        '<button data-filter="blind">Visibility gaps</button>'
        "</div>"
    )

    body = (
        f"{tiles}{_outcome_bar(summary)}"
        f"<h2>Cases</h2>{filters}"
        "<div class='table-wrap'><table id='cases'><thead><tr>"
        "<th>Rule</th><th>Technique</th><th>Test</th><th>Outcome</th><th>Status</th>"
        '<th class="num">Hits</th><th class="num">Telem</th><th class="num">Noise</th>'
        '<th class="num">Latency</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        f"{_coverage_table(coverage)}"
    )
    return _page(
        f"Run {run.run_id}",
        _nav("runs"),
        body,
        subtitle=f"{run.profile} - {run.backend} - {run.mode} mode",
    )


# -------------------------------------------------------------------- rule


def render_rule(rule_name: str, history: Sequence[dict[str, Any]], rule) -> str:
    if not history:
        body = f'<p class="empty">No recorded results for <code>{escape(rule_name)}</code>.</p>'
        return _page(rule_name, _nav("rules"), body)

    spark = "".join(
        f'<span class="spark {escape(str(row.get("outcome")))}" '
        f'title="{escape(str(row.get("run_id")))}: {escape(str(row.get("outcome")))}"></span>'
        for row in history
    )

    rows = "".join(
        "<tr>"
        f'<td><a href="/run/{escape(str(row.get("run_id")))}">'
        f"<code>{escape(str(row.get('run_id')))}</code></a></td>"
        f'<td class="mono">{escape(str(row.get("started_at") or "")[:19].replace("T", " "))}</td>'
        f"<td>{escape(str(row.get('profile') or ''))}</td>"
        f"<td><code>{escape(str(row.get('emulation_id') or ''))}</code></td>"
        f'<td><span class="pill {escape(str(row.get("outcome")))}">'
        f"{escape(str(row.get('outcome')))}</span></td>"
        f'<td class="num">{escape(format_duration(row.get("latency_seconds")))}</td>'
        "</tr>"
        for row in reversed(history)
    )

    meta = ""
    if rule is not None:
        meta = (
            f'<p class="lede">{escape(rule.description)}</p>'
            "<div class='kv'>"
            f"<div><b>severity</b>{escape(rule.severity.value)}</div>"
            f"<div><b>status</b>{escape(rule.status.value)}</div>"
            f"<div><b>technique</b>{escape(', '.join(rule.technique_ids) or '-')}</div>"
            f"<div><b>telemetry</b>{escape(', '.join(rule.telemetry) or '-')}</div>"
            f"<div><b>expects</b>{escape(rule.validation.expect.value)}</div>"
            f"<div><b>owner</b>{escape(rule.validation.owner or '-')}</div>"
            "</div>"
        )

    body = (
        f"{meta}"
        f"<h2>Outcome history</h2><div class='sparkline'>{spark}</div>"
        "<div class='table-wrap'><table><thead><tr><th>Run</th><th>Started</th>"
        '<th>Profile</th><th>Test</th><th>Outcome</th><th class="num">Latency</th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )
    return _page(rule_name, _nav("rules"), body, subtitle=rule.title if rule else "")


def render_rules(workspace, outcomes: dict[str, str]) -> str:
    rows = "".join(
        "<tr>"
        f'<td><a href="/rule/{escape(rule.name)}"><code>{escape(rule.name)}</code></a></td>'
        f"<td>{escape(rule.title[:60])}</td>"
        f"<td>{escape(rule.severity.value)}</td>"
        f"<td>{escape(rule.status.value)}</td>"
        f"<td>{escape(', '.join(rule.technique_ids) or '-')}</td>"
        f"<td>{escape(rule.validation.expect.value)}</td>"
        f'<td><span class="pill {escape(outcomes.get(rule.name, "skipped"))}">'
        f"{escape(outcomes.get(rule.name, 'untested'))}</span></td>"
        "</tr>"
        for rule in sorted(workspace.rules, key=lambda r: r.name)
    )
    body = (
        "<div class='table-wrap'><table><thead><tr><th>Rule</th><th>Title</th>"
        "<th>Severity</th><th>Status</th><th>Technique</th><th>Expects</th>"
        f"<th>Latest</th></tr></thead><tbody>{rows}</tbody></table></div>"
    )
    return _page("Rules", _nav("rules"), body, subtitle=f"{len(workspace.rules)} rules")


# ---------------------------------------------------------------- coverage


def render_coverage(run: RunRecord, workspace) -> str:
    coverage = build_coverage(run, reference=workspace.attack, targets=workspace.targets)
    body = (
        f'<div class="tiles">'
        f"{_tile('Detection', f'{coverage.detection_rate:.0%}', 'of scoreable cases', css='detected')}"
        f"{_tile('Visibility', f'{coverage.visibility_rate:.0%}', 'telemetry arrived')}"
        f"{_tile('Techniques', str(len(coverage.techniques)), 'measured')}"
        f"</div>"
        f"{_coverage_table(coverage)}"
        f"{_technique_table(coverage)}"
    )
    return _page("Coverage", _nav("coverage"), body, subtitle=f"from {run.run_id} ({run.profile})")


def _coverage_table(coverage) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{escape(t.name or t.tactic)}</td>"
        f"<td>{escape(t.priority)}</td>"
        f'<td class="num">{t.scoreable}</td>'
        f"<td>{_meter(t.detection_rate, t.target_detected)}</td>"
        f'<td class="num">{t.detection_rate:.0%}</td>'
        f"<td>{_meter(t.visibility_rate, t.target_visible)}</td>"
        f'<td class="num">{t.visibility_rate:.0%}</td>'
        f'<td><span class="pill {"pass" if t.meets_target else "fail"}">'
        f"{'on target' if t.meets_target else 'below'}</span></td>"
        "</tr>"
        for t in sorted(coverage.tactics.values(), key=lambda t: t.order)
        if t.scoreable
    )
    if not rows:
        return ""
    return (
        "<h2>Coverage by tactic</h2><div class='table-wrap'><table><thead><tr>"
        '<th>Tactic</th><th>Priority</th><th class="num">Cases</th><th>Detection</th>'
        '<th class="num">%</th><th>Visibility</th><th class="num">%</th><th></th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _technique_table(coverage) -> str:
    rows = "".join(
        "<tr>"
        f"<td><code>{escape(t.technique)}</code></td>"
        f"<td>{escape(t.name)}</td>"
        f"<td>{escape(t.priority)}</td>"
        f'<td class="num detected">{t.detected}</td>'
        f'<td class="num visible">{t.visible}</td>'
        f'<td class="num blind">{t.blind}</td>'
        f"<td>{escape(', '.join(t.rules))}</td>"
        f'<td class="note">{escape(", ".join(t.missing_telemetry))}</td>'
        "</tr>"
        for t in coverage.by_priority()
        if t.scoreable
    )
    if not rows:
        return ""
    return (
        "<h2>Techniques</h2><div class='table-wrap'><table><thead><tr>"
        '<th>ID</th><th>Name</th><th>Priority</th><th class="num">Det</th>'
        '<th class="num">Vis</th><th class="num">Blind</th><th>Rules</th>'
        f"<th>Missing telemetry</th></tr></thead><tbody>{rows}</tbody></table></div>"
    )


# ------------------------------------------------------------------ pieces


def render_error(status: int, message: str) -> str:
    body = f'<p class="empty">{escape(message)}</p><p><a href="/">Back to runs</a></p>'
    return _page(f"{status}", _nav(""), body)


def _tile(label: str, value: str, sub: str = "", *, css: str = "") -> str:
    return (
        f'<div class="tile {css}"><div class="label">{escape(label)}</div>'
        f'<div class="value">{escape(value)}</div>'
        f'<div class="sub">{escape(sub)}</div></div>'
    )


def _outcome_bar(summary) -> str:
    total = summary.total or 1
    segments = []
    legend = []
    for outcome in _OUTCOME_ORDER:
        count = summary.by_outcome.get(outcome.value, 0)
        if not count:
            continue
        segments.append(
            f'<span class="s-{outcome.value}" style="width:{count / total * 100:.2f}%" '
            f'title="{escape(_OUTCOME_LABEL[outcome])}: {count}"></span>'
        )
        legend.append(
            f'<span><i class="s-{outcome.value}"></i>'
            f"{escape(_OUTCOME_LABEL[outcome])} ({count})</span>"
        )
    if not segments:
        return ""
    return f'<div class="bar">{"".join(segments)}</div><div class="legend">{"".join(legend)}</div>'


def _meter(actual: float, target: float) -> str:
    below = "" if actual >= target else " below"
    return (
        f'<div class="meter{below}"><b style="width:{max(0.0, min(1.0, actual)) * 100:.1f}%"></b>'
        f'<i style="left:{max(0.0, min(1.0, target)) * 100:.1f}%"></i></div>'
    )


def _gate_pill(passed: bool | None) -> str:
    if passed is None:
        return '<span class="pill skipped">n/a</span>'
    return (
        '<span class="pill pass">pass</span>' if passed else '<span class="pill fail">fail</span>'
    )


def _compact(row: Iterable) -> str:
    if isinstance(row, dict):
        return "  ".join(f"{k}={v}" for k, v in row.items())
    return str(row)
