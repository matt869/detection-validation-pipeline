"""JUnit XML export.

Every CI system already knows how to render JUnit, so this is the cheapest way
to get validation results in front of engineers where they already look.

The mapping is chosen to keep CI honest:

* ``FAIL``  -> ``<failure>``. The rule did not do what it claims.
* ``ERROR`` -> ``<error>``. The pipeline could not tell, which is not the same
  as a pass and must not render as one.
* ``SKIPPED`` -> ``<skipped>``.
* ``UNEXPECTED_PASS`` -> passing, with the stale expectation in ``system-out``
  so it is visible without breaking the build.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from harness.core.models import CaseStatus, RunRecord
from harness.core.timeutil import to_iso

__all__ = ["render_junit"]


def render_junit(run: RunRecord, *, suite_name: str = "detection-validation") -> str:
    summary = run.summarise()
    failures = summary.by_status.get(CaseStatus.FAIL.value, 0)
    errors = summary.by_status.get(CaseStatus.ERROR.value, 0)
    skipped = summary.by_status.get(CaseStatus.SKIPPED.value, 0)

    suites = ET.Element(
        "testsuites",
        {
            "name": suite_name,
            "tests": str(summary.total),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{run.duration_seconds or 0:.3f}",
        },
    )
    suite = ET.SubElement(
        suites,
        "testsuite",
        {
            "name": f"{suite_name}.{run.profile}",
            "tests": str(summary.total),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{run.duration_seconds or 0:.3f}",
            "timestamp": to_iso(run.started_at) or "",
            "hostname": run.metadata.get("host", "unknown"),
        },
    )

    properties = ET.SubElement(suite, "properties")
    for key, value in {
        "run_id": run.run_id,
        "backend": run.backend,
        "mode": run.mode,
        "operator": run.operator,
        "detection_rate": f"{summary.detection_rate:.4f}",
        "visibility_rate": f"{summary.visibility_rate:.4f}",
    }.items():
        ET.SubElement(properties, "property", {"name": key, "value": str(value)})

    for result in run.results:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                # Classname groups by technique in most CI UIs, which is the
                # grouping a detection engineer actually wants.
                "classname": f"{run.profile}.{'-'.join(result.case.technique_ids) or 'unmapped'}",
                "name": f"{result.case.rule_name} :: {result.case.emulation_id}",
                "time": f"{result.latency_seconds or 0:.3f}",
            },
        )

        detail = "\n".join(result.notes)
        message = f"expected {result.case.expected.value}, observed {result.outcome.value}"

        if result.status is CaseStatus.FAIL:
            failure = ET.SubElement(
                case, "failure", {"message": message, "type": result.outcome.value}
            )
            failure.text = _body(result, detail)
        elif result.status is CaseStatus.ERROR:
            error = ET.SubElement(
                case, "error", {"message": result.error or "unknown error", "type": "error"}
            )
            error.text = _body(result, detail)
        elif result.status is CaseStatus.SKIPPED:
            ET.SubElement(case, "skipped", {"message": detail or "skipped"})
        elif result.status is CaseStatus.UNEXPECTED_PASS:
            out = ET.SubElement(case, "system-out")
            out.text = (
                f"Outcome '{result.outcome.value}' is better than the documented "
                f"expectation '{result.case.expected.value}'. Update the rule's "
                f"validation block so the expectation stops being stale.\n{detail}"
            )
        elif detail:
            out = ET.SubElement(case, "system-out")
            out.text = detail

    ET.indent(suites, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode")


def _body(result, detail: str) -> str:
    lines = [
        f"rule:      {result.case.rule_name}",
        f"technique: {', '.join(result.case.technique_ids) or '-'}",
        f"test:      {result.case.emulation_id}",
        f"outcome:   {result.outcome.value} (expected {result.case.expected.value})",
        f"telemetry: {', '.join(result.case.telemetry) or '-'}",
        f"hits:      detection={result.detection_hits} telemetry={result.telemetry_hits} "
        f"baseline={result.baseline_hits}",
        f"confidence: {result.confidence.value}",
    ]
    if result.queries:
        lines.append("")
        for kind, text in result.queries.items():
            lines.append(f"{kind} query: {text}")
    if detail:
        lines.extend(["", detail])
    return "\n".join(lines)
