"""ATT&CK Navigator layer export.

A layer file drops straight into the public Navigator, which is how most
organisations already look at coverage. Exporting *measured* coverage into that
view is the point: side by side with a layer built from rule counts, the
difference between "we have a rule" and "the rule fires" becomes visible to
people who do not read validation reports.

Colour encodes the three states, not a gradient of rule counts:

  green   detected - the control works
  amber   visible  - telemetry present, rule silent (detection gap)
  red     blind    - no telemetry (visibility gap)
  grey    untested
"""

from __future__ import annotations

from typing import Any

from harness.analysis.coverage import CoverageReport
from harness.core.models import RunRecord
from harness.core.timeutil import to_iso

__all__ = ["build_layer"]

_COLOURS = {
    "covered": "#2f9e5f",
    "partial": "#c9a227",
    "detection-gap": "#e08b1a",
    "visibility-gap": "#c0392b",
    "untested": "#8a939f",
}

_LEGEND = [
    {"label": "Detected - meets target", "color": _COLOURS["covered"]},
    {"label": "Partially detected - below target", "color": _COLOURS["partial"]},
    {"label": "Detection gap - telemetry present, no alert", "color": _COLOURS["detection-gap"]},
    {"label": "Visibility gap - no telemetry", "color": _COLOURS["visibility-gap"]},
    {"label": "Untested", "color": _COLOURS["untested"]},
]


def build_layer(
    run: RunRecord,
    coverage: CoverageReport,
    *,
    name: str | None = None,
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    """Build a Navigator 4.x layer document."""
    techniques: list[dict[str, Any]] = []
    all_ids = set(coverage.techniques)

    for technique in sorted(coverage.techniques.values(), key=lambda t: t.technique):
        # Expand a parent row only when we actually measured one of its
        # sub-techniques, so the layout does not open empty branches.
        has_measured_children = any(
            other.startswith(f"{technique.technique}.") for other in all_ids
        )
        status = technique.status
        score = round(technique.detection_rate * 100)
        comment = _comment(technique)

        entry: dict[str, Any] = {
            "techniqueID": technique.technique,
            "score": score,
            "color": _COLOURS.get(status, _COLOURS["untested"]),
            "comment": comment,
            "enabled": True,
            "metadata": [
                {"name": "status", "value": status},
                {"name": "detected", "value": str(technique.detected)},
                {"name": "detection gap", "value": str(technique.visible)},
                {"name": "visibility gap", "value": str(technique.blind)},
                {"name": "detection rate", "value": f"{technique.detection_rate:.0%}"},
                {"name": "target", "value": f"{technique.target_detected:.0%}"},
                {"name": "rules", "value": ", ".join(technique.rules) or "none"},
            ],
            "showSubtechniques": has_measured_children,
        }
        if technique.missing_telemetry:
            entry["metadata"].append(
                {"name": "missing telemetry", "value": ", ".join(technique.missing_telemetry)}
            )
        techniques.append(entry)

    for technique_id, reason in sorted(coverage.excluded.items()):
        techniques.append(
            {
                "techniqueID": technique_id,
                "enabled": False,
                "color": "#3f444c",
                "comment": f"Consciously out of scope: {reason}",
                "metadata": [{"name": "status", "value": "excluded"}],
            }
        )

    return {
        "name": name or f"Validated coverage - {run.profile}",
        "versions": {
            "attack": coverage.attack_version or "16",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": domain,
        "description": (
            f"Measured detection coverage from run {run.run_id} "
            f"({to_iso(run.started_at)}), backend {run.backend}. "
            "Score is the fraction of validation cases for the technique that "
            "actually fired - not the number of rules that exist for it."
        ),
        "filters": {
            "platforms": sorted({r.case.platform.title() for r in run.results if r.case.platform})
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [_COLOURS["visibility-gap"], _COLOURS["partial"], _COLOURS["covered"]],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": _LEGEND,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "metadata": [
            {"name": "run", "value": run.run_id},
            {"name": "profile", "value": run.profile},
            {"name": "backend", "value": run.backend},
            {"name": "overall detection", "value": f"{coverage.detection_rate:.0%}"},
            {"name": "overall visibility", "value": f"{coverage.visibility_rate:.0%}"},
        ],
    }


def _comment(technique: Any) -> str:
    parts = [
        f"{technique.detected} detected / {technique.visible} detection-gap / "
        f"{technique.blind} visibility-gap"
    ]
    if technique.rules:
        parts.append(f"rules: {', '.join(technique.rules)}")
    if technique.missing_telemetry:
        parts.append(f"missing telemetry: {', '.join(technique.missing_telemetry)}")
    if not technique.meets_detection_target and technique.scoreable:
        parts.append(
            f"below target ({technique.detection_rate:.0%} vs {technique.target_detected:.0%})"
        )
    return " | ".join(parts)
